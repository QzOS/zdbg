/*
 * tinyasm.c - tiny patch encoder for a fixed x86-64 subset.
 *
 * Encoding policy is deterministic: mnemonics pick the encoding
 * size, not the operand range.  jmp, jz, jnz are always rel32.
 * jmp8, jz8, jnz8 are always rel8.
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

static int
split_mn_op(const char *line, char *mn, size_t mnlen, const char **oprest)
{
	const char *p;
	size_t i;

	if (line == NULL || mn == NULL)
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
	if (oprest != NULL)
		*oprest = p;
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
encode_jmp_rel32(zaddr_t addr, zaddr_t target, struct ztinyasm *out)
{
	int64_t rel = (int64_t)target - (int64_t)(addr + 5);
	if (rel < -2147483648LL || rel > 2147483647LL)
		return -1;
	write_u8(out, 0xe9);
	write_rel32(out, (int32_t)rel);
	return 0;
}

static int
encode_jcc_rel32(zaddr_t addr, zaddr_t target, uint8_t cc, struct ztinyasm *out)
{
	int64_t rel = (int64_t)target - (int64_t)(addr + 6);
	if (rel < -2147483648LL || rel > 2147483647LL)
		return -1;
	write_u8(out, 0x0f);
	write_u8(out, cc);
	write_rel32(out, (int32_t)rel);
	return 0;
}

static int
encode_jmp_rel8(zaddr_t addr, zaddr_t target, struct ztinyasm *out)
{
	int64_t rel = (int64_t)target - (int64_t)(addr + 2);
	if (rel < -128 || rel > 127)
		return -1;
	write_u8(out, 0xeb);
	write_rel8(out, (int8_t)rel);
	return 0;
}

static int
encode_jcc_rel8(zaddr_t addr, zaddr_t target, uint8_t op, struct ztinyasm *out)
{
	int64_t rel = (int64_t)target - (int64_t)(addr + 2);
	if (rel < -128 || rel > 127)
		return -1;
	write_u8(out, op);
	write_rel8(out, (int8_t)rel);
	return 0;
}

int
ztinyasm_assemble(zaddr_t addr, const char *line, struct ztinyasm *out,
    const struct zregs *regs)
{
	char mn[16];
	const char *oprest = NULL;
	zaddr_t target = 0;

	if (line == NULL || out == NULL)
		return -1;
	memset(out, 0, sizeof(*out));

	if (split_mn_op(line, mn, sizeof(mn), &oprest) < 0)
		return -1;
	if (mn[0] == 0)
		return -1;
	lowercase(mn);

	/* zero-operand instructions */
	if (strcmp(mn, "nop") == 0) {
		write_u8(out, ZDBG_X86_NOP);
		return 0;
	}
	if (strcmp(mn, "int3") == 0) {
		write_u8(out, ZDBG_X86_INT3);
		return 0;
	}
	if (strcmp(mn, "ret") == 0) {
		write_u8(out, ZDBG_X86_RET);
		return 0;
	}

	/* one-operand (target) instructions */
	if (oprest == NULL || *oprest == 0)
		return -1;
	if (zexpr_eval(oprest, regs, &target) < 0)
		return -1;

	if (strcmp(mn, "jmp") == 0)
		return encode_jmp_rel32(addr, target, out);
	if (strcmp(mn, "jmp8") == 0)
		return encode_jmp_rel8(addr, target, out);

	if (strcmp(mn, "jz") == 0 || strcmp(mn, "je") == 0)
		return encode_jcc_rel32(addr, target, 0x84, out);
	if (strcmp(mn, "jnz") == 0 || strcmp(mn, "jne") == 0)
		return encode_jcc_rel32(addr, target, 0x85, out);

	if (strcmp(mn, "jz8") == 0 || strcmp(mn, "je8") == 0)
		return encode_jcc_rel8(addr, target, 0x74, out);
	if (strcmp(mn, "jnz8") == 0 || strcmp(mn, "jne8") == 0)
		return encode_jcc_rel8(addr, target, 0x75, out);

	return -1;
}

int
ztinyasm_patch(zaddr_t addr, size_t patch_len, const char *line,
    uint8_t *buf, size_t buflen, size_t *lenp, const struct zregs *regs)
{
	struct ztinyasm enc;
	size_t i;

	if (buf == NULL || patch_len == 0)
		return -1;
	if (patch_len > buflen)
		return -1;

	if (ztinyasm_assemble(addr, line, &enc, regs) < 0)
		return -1;
	if (enc.len > patch_len)
		return -1;

	for (i = 0; i < enc.len; i++)
		buf[i] = enc.code[i];
	for (; i < patch_len; i++)
		buf[i] = ZDBG_X86_NOP;

	if (lenp != NULL)
		*lenp = patch_len;
	return 0;
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
