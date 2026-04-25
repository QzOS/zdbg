/*
 * tinyasm.c - tiny patch encoder for a fixed x86-64 subset.
 *
 * Encoding policy is deterministic: mnemonics pick the encoding
 * size, not the operand range.  jmp, jz, jnz, call are always
 * rel32.  jmp8, jz8, jnz8 are always rel8.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "zdbg_arch.h"
#include "zdbg_expr.h"
#include "zdbg_tinyasm.h"

static void
lowercase(char *s)
{
	for (; *s; s++)
		*s = (char)tolower((unsigned char)*s);
}

static void
set_err(char *err, size_t errcap, const char *msg)
{
	if (err == NULL || errcap == 0 || msg == NULL)
		return;
	{
		size_t n = strlen(msg);
		if (n >= errcap)
			n = errcap - 1;
		memcpy(err, msg, n);
		err[n] = 0;
	}
}

static void
set_errf(char *err, size_t errcap, const char *fmt, const char *arg)
{
	if (err == NULL || errcap == 0)
		return;
	snprintf(err, errcap, fmt, arg);
}

/*
 * Split `line` into mnemonic (lowercased into `mn`) and
 * operand (the rest of the line after the mnemonic, with
 * leading whitespace skipped and trailing whitespace
 * trimmed) into `op` (size opcap).
 */
static int
split_mn_op(const char *line, char *mn, size_t mnlen,
    char *op, size_t opcap)
{
	const char *p;
	size_t i;
	size_t oplen;

	if (line == NULL || mn == NULL || op == NULL || opcap == 0)
		return -1;
	p = line;
	while (*p == ' ' || *p == '\t')
		p++;
	i = 0;
	while (*p && *p != ' ' && *p != '\t') {
		if (i + 1 >= mnlen)
			return -1;
		mn[i++] = *p++;
	}
	mn[i] = 0;
	while (*p == ' ' || *p == '\t')
		p++;
	oplen = strlen(p);
	if (oplen + 1 > opcap)
		return -1;
	memcpy(op, p, oplen + 1);
	/* trim trailing whitespace */
	while (oplen > 0 &&
	    (op[oplen - 1] == ' ' || op[oplen - 1] == '\t' ||
	     op[oplen - 1] == '\r' || op[oplen - 1] == '\n'))
		op[--oplen] = 0;
	return 0;
}

static void
write_u8(struct ztinyasm *out, uint8_t v)
{
	out->code[out->len++] = v;
}

static void
write_rel8(struct ztinyasm *out, int8_t v)
{
	out->code[out->len++] = (uint8_t)v;
}

static void
write_rel32(struct ztinyasm *out, int32_t v)
{
	out->code[out->len++] = (uint8_t)(v & 0xff);
	out->code[out->len++] = (uint8_t)((v >> 8) & 0xff);
	out->code[out->len++] = (uint8_t)((v >> 16) & 0xff);
	out->code[out->len++] = (uint8_t)((v >> 24) & 0xff);
}

static int
encode_jmp_rel32(zaddr_t addr, zaddr_t target, struct ztinyasm *out,
    char *err, size_t errcap)
{
	int64_t rel = (int64_t)target - (int64_t)(addr + 5);
	if (rel < -2147483648LL || rel > 2147483647LL) {
		set_err(err, errcap, "jmp target out of rel32 range");
		return -1;
	}
	write_u8(out, 0xe9);
	write_rel32(out, (int32_t)rel);
	return 0;
}

static int
encode_call_rel32(zaddr_t addr, zaddr_t target, struct ztinyasm *out,
    char *err, size_t errcap)
{
	int64_t rel = (int64_t)target - (int64_t)(addr + 5);
	if (rel < -2147483648LL || rel > 2147483647LL) {
		set_err(err, errcap, "call target out of rel32 range");
		return -1;
	}
	write_u8(out, 0xe8);
	write_rel32(out, (int32_t)rel);
	return 0;
}

static int
encode_jcc_rel32(zaddr_t addr, zaddr_t target, uint8_t cc,
    struct ztinyasm *out, const char *mn, char *err, size_t errcap)
{
	int64_t rel = (int64_t)target - (int64_t)(addr + 6);
	if (rel < -2147483648LL || rel > 2147483647LL) {
		set_errf(err, errcap, "%s target out of rel32 range", mn);
		return -1;
	}
	write_u8(out, 0x0f);
	write_u8(out, cc);
	write_rel32(out, (int32_t)rel);
	return 0;
}

static int
encode_jmp_rel8(zaddr_t addr, zaddr_t target, struct ztinyasm *out,
    char *err, size_t errcap)
{
	int64_t rel = (int64_t)target - (int64_t)(addr + 2);
	if (rel < -128 || rel > 127) {
		set_err(err, errcap, "jmp8 target out of rel8 range");
		return -1;
	}
	write_u8(out, 0xeb);
	write_rel8(out, (int8_t)rel);
	return 0;
}

static int
encode_jcc_rel8(zaddr_t addr, zaddr_t target, uint8_t op,
    struct ztinyasm *out, const char *mn, char *err, size_t errcap)
{
	int64_t rel = (int64_t)target - (int64_t)(addr + 2);
	if (rel < -128 || rel > 127) {
		set_errf(err, errcap, "%s target out of rel8 range", mn);
		return -1;
	}
	write_u8(out, op);
	write_rel8(out, (int8_t)rel);
	return 0;
}

/*
 * Write `movabs r11, imm64` (49 BB imm64) followed by either
 * `jmp r11` (41 FF E3) or `call r11` (41 FF D3).  This is the
 * common tail of jmpabs/callabs/jzabs/jnzabs and clobbers r11.
 */
static void
write_imm64_le(struct ztinyasm *out, uint64_t v)
{
	int i;
	for (i = 0; i < 8; i++)
		out->code[out->len++] = (uint8_t)((v >> (i * 8)) & 0xff);
}

static void
write_movabs_r11_jmp_or_call(struct ztinyasm *out, uint64_t target,
    int is_call)
{
	/* movabs r11, imm64 : 49 BB imm64 */
	write_u8(out, 0x49);
	write_u8(out, 0xbb);
	write_imm64_le(out, target);
	/* jmp r11  : 41 FF E3   /  call r11 : 41 FF D3 */
	write_u8(out, 0x41);
	write_u8(out, 0xff);
	write_u8(out, is_call ? 0xd3 : 0xe3);
}

static int
encode_jmpabs(zaddr_t target, struct ztinyasm *out)
{
	write_movabs_r11_jmp_or_call(out, (uint64_t)target, 0);
	return 0;
}

static int
encode_callabs(zaddr_t target, struct ztinyasm *out)
{
	write_movabs_r11_jmp_or_call(out, (uint64_t)target, 1);
	return 0;
}

/*
 * Conditional absolute pseudo: skip the 13-byte absolute jmp
 * sequence with an inverted rel8 conditional jump.
 *
 *   jzabs  TARGET -> 75 0D | 49 BB <imm64> 41 FF E3   (jnz +13)
 *   jnzabs TARGET -> 74 0D | 49 BB <imm64> 41 FF E3   (jz  +13)
 */
static int
encode_jccabs(zaddr_t target, uint8_t skip_op, struct ztinyasm *out)
{
	write_u8(out, skip_op);
	write_u8(out, 0x0d); /* skip the 13-byte absolute sequence */
	write_movabs_r11_jmp_or_call(out, (uint64_t)target, 0);
	return 0;
}

/*
 * Legacy resolver used by the old API: only numbers and
 * registers via zexpr_eval().
 */
static int
legacy_resolve(void *arg, const char *expr, zaddr_t *out)
{
	const struct zregs *regs = (const struct zregs *)arg;
	return zexpr_eval(expr, regs, out);
}

int
ztinyasm_assemble_ex(zaddr_t addr, const char *line, struct ztinyasm *out,
    ztinyasm_resolve_fn resolve, void *resolve_arg,
    char *err, size_t errcap)
{
	char mn[16];
	char op[256];
	zaddr_t target = 0;

	if (err != NULL && errcap > 0)
		err[0] = 0;
	if (line == NULL || out == NULL) {
		set_err(err, errcap, "internal: null arg");
		return -1;
	}
	memset(out, 0, sizeof(*out));

	if (split_mn_op(line, mn, sizeof(mn), op, sizeof(op)) < 0) {
		set_err(err, errcap, "instruction too long");
		return -1;
	}
	if (mn[0] == 0) {
		set_err(err, errcap, "missing instruction");
		return -1;
	}
	lowercase(mn);

	/* zero-operand instructions */
	if (strcmp(mn, "nop") == 0 || strcmp(mn, "int3") == 0 ||
	    strcmp(mn, "ret") == 0) {
		if (op[0] != 0) {
			set_errf(err, errcap,
			    "%s takes no operand", mn);
			return -1;
		}
		if (strcmp(mn, "nop") == 0)
			write_u8(out, ZDBG_X86_NOP);
		else if (strcmp(mn, "int3") == 0)
			write_u8(out, ZDBG_X86_INT3);
		else
			write_u8(out, ZDBG_X86_RET);
		return 0;
	}

	/* one-operand (target) instructions */
	if (op[0] == 0) {
		set_errf(err, errcap, "missing operand for %s", mn);
		return -1;
	}
	if (resolve == NULL) {
		set_err(err, errcap, "no operand resolver");
		return -1;
	}
	if (resolve(resolve_arg, op, &target) < 0) {
		set_errf(err, errcap, "bad target expression: %s", op);
		return -1;
	}

	if (strcmp(mn, "jmp") == 0)
		return encode_jmp_rel32(addr, target, out, err, errcap);
	if (strcmp(mn, "jmp8") == 0)
		return encode_jmp_rel8(addr, target, out, err, errcap);
	if (strcmp(mn, "call") == 0)
		return encode_call_rel32(addr, target, out, err, errcap);

	if (strcmp(mn, "jz") == 0 || strcmp(mn, "je") == 0)
		return encode_jcc_rel32(addr, target, 0x84, out, mn,
		    err, errcap);
	if (strcmp(mn, "jnz") == 0 || strcmp(mn, "jne") == 0)
		return encode_jcc_rel32(addr, target, 0x85, out, mn,
		    err, errcap);

	if (strcmp(mn, "jz8") == 0 || strcmp(mn, "je8") == 0)
		return encode_jcc_rel8(addr, target, 0x74, out, mn,
		    err, errcap);
	if (strcmp(mn, "jnz8") == 0 || strcmp(mn, "jne8") == 0)
		return encode_jcc_rel8(addr, target, 0x75, out, mn,
		    err, errcap);

	/* Absolute pseudo-instructions via r11 scratch (clobbered).
	 * No rel32 range error: target is loaded as a full imm64. */
	if (strcmp(mn, "jmpabs") == 0)
		return encode_jmpabs(target, out);
	if (strcmp(mn, "callabs") == 0)
		return encode_callabs(target, out);
	if (strcmp(mn, "jzabs") == 0 || strcmp(mn, "jeabs") == 0)
		/* take when ZF==1: skip when ZF==0 -> jnz8 +13 */
		return encode_jccabs(target, 0x75, out);
	if (strcmp(mn, "jnzabs") == 0 || strcmp(mn, "jneabs") == 0)
		/* take when ZF==0: skip when ZF==1 -> jz8 +13 */
		return encode_jccabs(target, 0x74, out);

	set_errf(err, errcap, "unknown instruction: %s", mn);
	return -1;
}

int
ztinyasm_assemble(zaddr_t addr, const char *line, struct ztinyasm *out,
    const struct zregs *regs)
{
	return ztinyasm_assemble_ex(addr, line, out,
	    legacy_resolve, (void *)regs, NULL, 0);
}

int
ztinyasm_patch_ex(zaddr_t addr, size_t patch_len, const char *line,
    uint8_t *buf, size_t buflen, size_t *lenp,
    ztinyasm_resolve_fn resolve, void *resolve_arg,
    char *err, size_t errcap)
{
	struct ztinyasm enc;
	size_t i;

	if (err != NULL && errcap > 0)
		err[0] = 0;
	if (buf == NULL || patch_len == 0) {
		set_err(err, errcap, "bad patch buffer");
		return -1;
	}
	if (patch_len > buflen) {
		set_err(err, errcap, "output buffer too small");
		return -1;
	}

	if (ztinyasm_assemble_ex(addr, line, &enc, resolve, resolve_arg,
	    err, errcap) < 0)
		return -1;
	if (enc.len > patch_len) {
		if (err != NULL && errcap > 0)
			snprintf(err, errcap,
			    "instruction length %u exceeds patch length %u",
			    (unsigned)enc.len, (unsigned)patch_len);
		return -1;
	}

	for (i = 0; i < enc.len; i++)
		buf[i] = enc.code[i];
	for (; i < patch_len; i++)
		buf[i] = ZDBG_X86_NOP;

	if (lenp != NULL)
		*lenp = patch_len;
	return 0;
}

int
ztinyasm_patch(zaddr_t addr, size_t patch_len, const char *line,
    uint8_t *buf, size_t buflen, size_t *lenp, const struct zregs *regs)
{
	return ztinyasm_patch_ex(addr, patch_len, line, buf, buflen, lenp,
	    legacy_resolve, (void *)regs, NULL, 0);
}

int
zpatch_invert_jcc(uint8_t *buf, size_t len, size_t *usedp)
{
	if (buf == NULL)
		return -1;

	if (len >= 2 && buf[0] == 0x74) {
		buf[0] = 0x75;
		if (usedp)
			*usedp = 2;
		return 0;
	}
	if (len >= 2 && buf[0] == 0x75) {
		buf[0] = 0x74;
		if (usedp)
			*usedp = 2;
		return 0;
	}
	if (len >= 6 && buf[0] == 0x0f && buf[1] == 0x84) {
		buf[1] = 0x85;
		if (usedp)
			*usedp = 6;
		return 0;
	}
	if (len >= 6 && buf[0] == 0x0f && buf[1] == 0x85) {
		buf[1] = 0x84;
		if (usedp)
			*usedp = 6;
		return 0;
	}
	return -1;
}
