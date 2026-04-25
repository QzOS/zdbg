/*
 * arch_aarch64_asm.c - AArch64 phase-1 tiny patch encoder.
 *
 * Narrow scope: assemble single fixed-width 4-byte AArch64
 * instructions for use by zdbg's `a` and `pa` commands.  Not a
 * full assembler.  No labels, no literal pools, no relocations,
 * no multi-instruction expansions.
 *
 * Coverage:
 *   nop, brk #imm, svc #imm, ret, ret xN
 *   br xN, blr xN
 *   b TARGET, bl TARGET
 *   b.cond TARGET (eq/ne/cs/hs/cc/lo/mi/pl/vs/vc/hi/ls/ge/lt/gt/le)
 *   cbz/cbnz xN|wN, TARGET
 *   tbz/tbnz xN|wN, #bit, TARGET
 *   add/sub xD|wD, xN|wN, #imm (with sh=0 or sh=12 multiples)
 *   cmp xN|wN, #imm  (alias of subs xzr/wzr, ...)
 *   mov xD, sp / mov sp, xN  (add #0 alias)
 *
 * All encodings are emitted little-endian.  TARGET expressions
 * are resolved through the supplied zarch_resolve_fn.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "zdbg_arch.h"
#include "zdbg_arch_aarch64.h"

#define AARCH64_INSN_BYTES 4
#define AARCH64_NOP_WORD   0xd503201fu

/* --- error/string helpers ------------------------------------- */

static void
set_err(char *err, size_t errcap, const char *msg)
{
	size_t n;

	if (err == NULL || errcap == 0 || msg == NULL)
		return;
	n = strlen(msg);
	if (n >= errcap)
		n = errcap - 1;
	memcpy(err, msg, n);
	err[n] = 0;
}

static void
set_errf1s(char *err, size_t errcap, const char *fmt, const char *a)
{
	if (err == NULL || errcap == 0)
		return;
	snprintf(err, errcap, fmt, a);
}

static void
put32le(uint8_t *p, uint32_t w)
{
	p[0] = (uint8_t)(w);
	p[1] = (uint8_t)(w >> 8);
	p[2] = (uint8_t)(w >> 16);
	p[3] = (uint8_t)(w >> 24);
}

static char
lc(char c)
{
	return (char)tolower((unsigned char)c);
}

static int
streq_ci(const char *a, const char *b)
{
	while (*a && *b) {
		if (lc(*a) != lc(*b))
			return 0;
		a++; b++;
	}
	return *a == 0 && *b == 0;
}

/* Trim leading/trailing ASCII whitespace in-place. */
static void
trim(char *s)
{
	size_t n;
	char *p;

	if (s == NULL)
		return;
	p = s;
	while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
		p++;
	if (p != s)
		memmove(s, p, strlen(p) + 1);
	n = strlen(s);
	while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' ||
	    s[n - 1] == '\r' || s[n - 1] == '\n'))
		s[--n] = 0;
}

/* Lowercase a copy of `src` into `dst` (capped at `cap`). */
static void
copy_lower(char *dst, size_t cap, const char *src)
{
	size_t i;

	if (cap == 0)
		return;
	for (i = 0; i + 1 < cap && src[i]; i++)
		dst[i] = lc(src[i]);
	dst[i] = 0;
}

/* --- mnemonic / operand split --------------------------------- */

/*
 * Split `line` into `mn` (lowercased mnemonic) and the rest into
 * `op`.  Returns 0 on success, -1 on overflow.
 */
static int
split_mn_op(const char *line, char *mn, size_t mnlen,
    char *op, size_t opcap)
{
	const char *p;
	size_t i;
	size_t oplen;

	if (line == NULL || mn == NULL || op == NULL ||
	    mnlen == 0 || opcap == 0)
		return -1;
	p = line;
	while (*p == ' ' || *p == '\t')
		p++;
	i = 0;
	while (*p && *p != ' ' && *p != '\t') {
		if (i + 1 >= mnlen)
			return -1;
		mn[i++] = lc(*p);
		p++;
	}
	mn[i] = 0;
	while (*p == ' ' || *p == '\t')
		p++;
	oplen = strlen(p);
	if (oplen + 1 > opcap)
		return -1;
	memcpy(op, p, oplen + 1);
	while (oplen > 0 && (op[oplen - 1] == ' ' ||
	    op[oplen - 1] == '\t' || op[oplen - 1] == '\r' ||
	    op[oplen - 1] == '\n'))
		op[--oplen] = 0;
	return 0;
}

/*
 * Split a comma-separated operand list into up to `maxn` fields.
 * Each field has surrounding whitespace trimmed.  Returns the
 * number of fields on success, -1 on overflow.
 */
static int
split_commas(const char *src, char fields[][128], int maxn)
{
	int n;
	size_t i;
	size_t flen;

	n = 0;
	i = 0;
	flen = 0;
	if (src == NULL)
		return 0;
	for (;;) {
		char c = src[i];
		if (c == ',' || c == 0) {
			if (n >= maxn)
				return -1;
			fields[n][flen] = 0;
			trim(fields[n]);
			n++;
			flen = 0;
			if (c == 0)
				break;
		} else {
			if (flen + 1 >= 128)
				return -1;
			fields[n][flen++] = c;
		}
		i++;
	}
	/* If src was empty, return 0 (no fields). */
	if (n == 1 && fields[0][0] == 0)
		return 0;
	return n;
}

/* --- numeric immediate parser --------------------------------- */

/*
 * Parse an unsigned immediate.  Accepts optional leading '#'.
 * Decimal by default, 0x/0X for hex.  Returns 0 on success and
 * -1 on parse error.
 */
static int
parse_uimm(const char *s, uint64_t *vp)
{
	uint64_t v;
	int base;
	const char *p;

	if (s == NULL || *s == 0)
		return -1;
	p = s;
	while (*p == ' ' || *p == '\t')
		p++;
	if (*p == '#')
		p++;
	while (*p == ' ' || *p == '\t')
		p++;
	if (*p == 0)
		return -1;
	base = 10;
	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
		base = 16;
		p += 2;
		if (*p == 0)
			return -1;
	}
	v = 0;
	while (*p) {
		unsigned d;
		char c = lc(*p);
		if (c >= '0' && c <= '9')
			d = (unsigned)(c - '0');
		else if (base == 16 && c >= 'a' && c <= 'f')
			d = (unsigned)(c - 'a') + 10;
		else
			break;
		if (d >= (unsigned)base)
			return -1;
		v = v * (uint64_t)base + (uint64_t)d;
		p++;
	}
	while (*p == ' ' || *p == '\t')
		p++;
	if (*p != 0)
		return -1;
	*vp = v;
	return 0;
}

/* --- register parser ------------------------------------------ */

/*
 * Parse an AArch64 register operand.  Outputs the register number
 * (0..31) and width (32 or 64).  When the special name SP is used
 * `is_sp` is set to 1; when ZR is used `is_zr` is set to 1; both
 * cases also report number 31.
 *
 * Recognized: x0..x30, w0..w30, sp, wsp, xzr, wzr.
 */
static int
parse_reg(const char *s, unsigned *nump, int *widthp,
    int *is_sp, int *is_zr)
{
	char buf[16];
	size_t i;
	const char *p;
	unsigned n;

	if (s == NULL)
		return -1;
	p = s;
	while (*p == ' ' || *p == '\t')
		p++;
	for (i = 0; i + 1 < sizeof(buf) && p[i]; i++)
		buf[i] = lc(p[i]);
	buf[i] = 0;
	/* trim trailing spaces */
	while (i > 0 && (buf[i - 1] == ' ' || buf[i - 1] == '\t'))
		buf[--i] = 0;

	if (buf[0] == 0)
		return -1;

	*is_sp = 0;
	*is_zr = 0;

	if (strcmp(buf, "sp") == 0) {
		*nump = 31;
		*widthp = 64;
		*is_sp = 1;
		return 0;
	}
	if (strcmp(buf, "wsp") == 0) {
		*nump = 31;
		*widthp = 32;
		*is_sp = 1;
		return 0;
	}
	if (strcmp(buf, "xzr") == 0) {
		*nump = 31;
		*widthp = 64;
		*is_zr = 1;
		return 0;
	}
	if (strcmp(buf, "wzr") == 0) {
		*nump = 31;
		*widthp = 32;
		*is_zr = 1;
		return 0;
	}
	if ((buf[0] == 'x' || buf[0] == 'w') && buf[1] != 0) {
		uint64_t u;
		if (parse_uimm(buf + 1, &u) < 0)
			return -1;
		if (u > 30)
			return -1;
		n = (unsigned)u;
		*nump = n;
		*widthp = (buf[0] == 'x') ? 64 : 32;
		return 0;
	}
	return -1;
}

/* Parse an X-class general register that can be SP (rd/rn for
 * ADD imm) but not the zero register form. */
static int
parse_xreg_sp_ok(const char *s, unsigned *nump, char *err, size_t errcap)
{
	int width;
	int is_sp, is_zr;

	if (parse_reg(s, nump, &width, &is_sp, &is_zr) < 0 ||
	    width != 64 || is_zr) {
		set_errf1s(err, errcap, "bad register: %s", s);
		return -1;
	}
	return 0;
}

/* Parse an X-class general register that disallows SP. */
static int
parse_xreg_no_sp(const char *s, unsigned *nump, char *err, size_t errcap)
{
	int width;
	int is_sp, is_zr;

	if (parse_reg(s, nump, &width, &is_sp, &is_zr) < 0 ||
	    width != 64 || is_sp || is_zr) {
		set_errf1s(err, errcap, "bad register: %s", s);
		return -1;
	}
	return 0;
}

/* Parse a W-class register that may be WSP. */
static int
parse_wreg_sp_ok(const char *s, unsigned *nump, char *err, size_t errcap)
{
	int width;
	int is_sp, is_zr;

	if (parse_reg(s, nump, &width, &is_sp, &is_zr) < 0 ||
	    width != 32 || is_zr) {
		set_errf1s(err, errcap, "bad register: %s", s);
		return -1;
	}
	return 0;
}

/* --- condition codes ------------------------------------------ */

static int
cond_code(const char *suf, unsigned *cp)
{
	struct { const char *n; unsigned c; } tbl[] = {
		{ "eq", 0 }, { "ne", 1 },
		{ "cs", 2 }, { "hs", 2 },
		{ "cc", 3 }, { "lo", 3 },
		{ "mi", 4 }, { "pl", 5 },
		{ "vs", 6 }, { "vc", 7 },
		{ "hi", 8 }, { "ls", 9 },
		{ "ge", 10 }, { "lt", 11 },
		{ "gt", 12 }, { "le", 13 }
	};
	size_t i;

	for (i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
		if (streq_ci(suf, tbl[i].n)) {
			*cp = tbl[i].c;
			return 0;
		}
	}
	return -1;
}

/* --- branch helpers ------------------------------------------- */

static int
resolve_target(zarch_resolve_fn resolve, void *resolve_arg,
    const char *expr, zaddr_t *out, char *err, size_t errcap)
{
	if (resolve == NULL) {
		set_err(err, errcap, "no operand resolver");
		return -1;
	}
	if (resolve(resolve_arg, expr, out) < 0) {
		set_errf1s(err, errcap, "bad target expression: %s", expr);
		return -1;
	}
	return 0;
}

/*
 * Compute branch byte offset and verify alignment.  Returns 0 on
 * success and writes signed offset to *offp.  Errors on
 * misalignment.
 */
static int
branch_offset(zaddr_t addr, zaddr_t target, int64_t *offp,
    char *err, size_t errcap)
{
	int64_t off;

	off = (int64_t)((uint64_t)target - (uint64_t)addr);
	if ((off & 3) != 0) {
		set_err(err, errcap,
		    "branch target must be 4-byte aligned");
		return -1;
	}
	*offp = off;
	return 0;
}

/* --- encoders ------------------------------------------------- */

static int
enc_b(zaddr_t addr, zaddr_t target, int with_link, uint32_t *wp,
    char *err, size_t errcap)
{
	int64_t off;
	uint32_t base;

	if (branch_offset(addr, target, &off, err, errcap) < 0)
		return -1;
	if (off < -(int64_t)0x08000000 || off > (int64_t)0x07fffffc) {
		set_err(err, errcap, "branch target out of range");
		return -1;
	}
	base = with_link ? 0x94000000u : 0x14000000u;
	*wp = base | (uint32_t)((off >> 2) & 0x03ffffff);
	return 0;
}

static int
enc_bcond(zaddr_t addr, zaddr_t target, unsigned cond, uint32_t *wp,
    char *err, size_t errcap)
{
	int64_t off;

	if (branch_offset(addr, target, &off, err, errcap) < 0)
		return -1;
	if (off < -(int64_t)0x100000 || off > (int64_t)0x0ffffc) {
		set_err(err, errcap, "branch target out of range");
		return -1;
	}
	*wp = 0x54000000u |
	    (uint32_t)(((off >> 2) & 0x7ffff) << 5) |
	    (cond & 0xf);
	return 0;
}

static int
enc_cbz(zaddr_t addr, zaddr_t target, int sf, int nz, unsigned rt,
    uint32_t *wp, char *err, size_t errcap)
{
	int64_t off;
	uint32_t base;

	if (branch_offset(addr, target, &off, err, errcap) < 0)
		return -1;
	if (off < -(int64_t)0x100000 || off > (int64_t)0x0ffffc) {
		set_err(err, errcap, "branch target out of range");
		return -1;
	}
	base = nz ? 0x35000000u : 0x34000000u;
	if (sf)
		base |= 0x80000000u;
	*wp = base |
	    (uint32_t)(((off >> 2) & 0x7ffff) << 5) |
	    (rt & 0x1f);
	return 0;
}

static int
enc_tbz(zaddr_t addr, zaddr_t target, int wide, unsigned bit,
    int nz, unsigned rt, uint32_t *wp, char *err, size_t errcap)
{
	int64_t off;
	uint32_t base;
	uint32_t b40, b5;

	if (!wide && bit > 31) {
		set_err(err, errcap, "tbz/tbnz bit out of range");
		return -1;
	}
	if (wide && bit > 63) {
		set_err(err, errcap, "tbz/tbnz bit out of range");
		return -1;
	}
	if (branch_offset(addr, target, &off, err, errcap) < 0)
		return -1;
	if (off < -(int64_t)0x8000 || off > (int64_t)0x7ffc) {
		set_err(err, errcap, "branch target out of range");
		return -1;
	}
	base = nz ? 0x37000000u : 0x36000000u;
	b40 = bit & 0x1f;
	b5 = (bit >> 5) & 0x1;
	*wp = base | (b5 << 31) | (b40 << 19) |
	    (uint32_t)(((off >> 2) & 0x3fff) << 5) |
	    (rt & 0x1f);
	return 0;
}

/*
 * Encode an ADD/SUB immediate (with optional S bit for cmp).
 * `sf` is 0 for w-form, 1 for x-form.  `op` is 0 for add, 1 for
 * sub.  `S` is 0 for normal, 1 for subs/cmp.  `imm` must fit in
 * 12 bits (sh=0) or be a multiple of 4096 with imm/4096 fitting
 * in 12 bits (sh=1).
 */
static int
enc_addsub_imm(int sf, int op, int S, uint64_t imm, unsigned rn,
    unsigned rd, uint32_t *wp, char *err, size_t errcap)
{
	uint32_t base;
	unsigned sh;
	uint64_t imm12;

	if (imm <= 0xfff) {
		sh = 0;
		imm12 = imm;
	} else if ((imm & 0xfff) == 0 && (imm >> 12) <= 0xfff) {
		sh = 1;
		imm12 = imm >> 12;
	} else {
		set_err(err, errcap, "immediate out of range");
		return -1;
	}
	base = 0x11000000u;
	if (sf) base |= 0x80000000u;
	if (op) base |= 0x40000000u;
	if (S)  base |= 0x20000000u;
	*wp = base | ((uint32_t)sh << 22) |
	    ((uint32_t)(imm12 & 0xfff) << 10) |
	    ((rn & 0x1f) << 5) | (rd & 0x1f);
	return 0;
}

/* --- per-mnemonic encoders ------------------------------------ */

static int
do_zero_op(const char *mn, const char *op, uint32_t *wp,
    char *err, size_t errcap)
{
	int is_nop = (strcmp(mn, "nop") == 0);
	int is_int3 = (strcmp(mn, "int3") == 0);
	int is_ret = (strcmp(mn, "ret") == 0);

	if (!is_nop && !is_int3 && !is_ret)
		return 1; /* not handled */
	if (is_ret && op[0] != 0)
		return 1; /* let do_ret_xn handle ret xN */
	if (op[0] != 0) {
		set_errf1s(err, errcap, "%s takes no operand", mn);
		return -1;
	}
	if (is_nop)
		*wp = AARCH64_NOP_WORD;
	else if (is_ret)
		*wp = 0xd65f03c0u;
	else
		*wp = 0xd4200000u;
	return 0;
}

static int
do_brk_svc(const char *mn, const char *op, uint32_t *wp,
    char *err, size_t errcap)
{
	uint64_t imm;
	uint32_t base;

	if (strcmp(mn, "brk") == 0)
		base = 0xd4200000u;
	else if (strcmp(mn, "svc") == 0)
		base = 0xd4000001u;
	else
		return 1;

	if (op[0] == 0) {
		set_errf1s(err, errcap, "missing operand for %s", mn);
		return -1;
	}
	if (parse_uimm(op, &imm) < 0 || imm > 0xffff) {
		set_err(err, errcap, "immediate out of range");
		return -1;
	}
	*wp = base | (uint32_t)((imm & 0xffff) << 5);
	return 0;
}

static int
do_ret_xn(const char *mn, const char *op, uint32_t *wp,
    char *err, size_t errcap)
{
	unsigned rn;

	if (strcmp(mn, "ret") != 0)
		return 1;
	if (op[0] == 0) {
		*wp = 0xd65f03c0u;
		return 0;
	}
	if (parse_xreg_no_sp(op, &rn, err, errcap) < 0)
		return -1;
	*wp = 0xd65f0000u | (rn << 5);
	return 0;
}

static int
do_br_blr(const char *mn, const char *op, uint32_t *wp,
    char *err, size_t errcap)
{
	unsigned rn;
	uint32_t base;

	if (strcmp(mn, "br") == 0)
		base = 0xd61f0000u;
	else if (strcmp(mn, "blr") == 0)
		base = 0xd63f0000u;
	else
		return 1;
	if (op[0] == 0) {
		set_errf1s(err, errcap, "missing operand for %s", mn);
		return -1;
	}
	if (parse_xreg_no_sp(op, &rn, err, errcap) < 0)
		return -1;
	*wp = base | (rn << 5);
	return 0;
}

static int
do_b_bl(const char *mn, const char *op, zaddr_t addr,
    zarch_resolve_fn resolve, void *resolve_arg,
    uint32_t *wp, char *err, size_t errcap)
{
	int with_link;
	zaddr_t target;

	if (strcmp(mn, "b") == 0)
		with_link = 0;
	else if (strcmp(mn, "bl") == 0)
		with_link = 1;
	else
		return 1;
	if (op[0] == 0) {
		set_errf1s(err, errcap, "missing operand for %s", mn);
		return -1;
	}
	if (resolve_target(resolve, resolve_arg, op, &target,
	    err, errcap) < 0)
		return -1;
	return enc_b(addr, target, with_link, wp, err, errcap);
}

static int
do_bcond(const char *mn, const char *op, zaddr_t addr,
    zarch_resolve_fn resolve, void *resolve_arg,
    uint32_t *wp, char *err, size_t errcap)
{
	const char *suf;
	unsigned cond;
	zaddr_t target;
	char tmp[8];

	suf = NULL;
	if (mn[0] == 'b' && mn[1] == '.' && mn[2] != 0)
		suf = mn + 2;
	else if ((mn[0] == 'b') && mn[1] != 0 && mn[2] != 0 &&
	    mn[3] == 0) {
		/* Aliases beq/bne. */
		if (strcmp(mn, "beq") == 0 || strcmp(mn, "bne") == 0) {
			tmp[0] = mn[1];
			tmp[1] = mn[2];
			tmp[2] = 0;
			suf = tmp;
		}
	}
	if (suf == NULL)
		return 1;
	if (cond_code(suf, &cond) < 0) {
		set_errf1s(err, errcap, "bad condition: %s", mn);
		return -1;
	}
	if (op[0] == 0) {
		set_errf1s(err, errcap, "missing operand for %s", mn);
		return -1;
	}
	if (resolve_target(resolve, resolve_arg, op, &target,
	    err, errcap) < 0)
		return -1;
	return enc_bcond(addr, target, cond, wp, err, errcap);
}

static int
do_cbz(const char *mn, const char *op, zaddr_t addr,
    zarch_resolve_fn resolve, void *resolve_arg,
    uint32_t *wp, char *err, size_t errcap)
{
	int nz;
	char fields[2][128];
	int n;
	unsigned rt;
	int width;
	int is_sp, is_zr;
	zaddr_t target;

	if (strcmp(mn, "cbz") == 0)
		nz = 0;
	else if (strcmp(mn, "cbnz") == 0)
		nz = 1;
	else
		return 1;
	n = split_commas(op, fields, 2);
	if (n != 2) {
		set_errf1s(err, errcap, "bad operands for %s", mn);
		return -1;
	}
	if (parse_reg(fields[0], &rt, &width, &is_sp, &is_zr) < 0 ||
	    is_sp) {
		set_errf1s(err, errcap, "bad register: %s", fields[0]);
		return -1;
	}
	if (resolve_target(resolve, resolve_arg, fields[1], &target,
	    err, errcap) < 0)
		return -1;
	return enc_cbz(addr, target, width == 64, nz, rt, wp,
	    err, errcap);
}

static int
do_tbz(const char *mn, const char *op, zaddr_t addr,
    zarch_resolve_fn resolve, void *resolve_arg,
    uint32_t *wp, char *err, size_t errcap)
{
	int nz;
	char fields[3][128];
	int n;
	unsigned rt;
	int width;
	int is_sp, is_zr;
	uint64_t bit;
	zaddr_t target;

	if (strcmp(mn, "tbz") == 0)
		nz = 0;
	else if (strcmp(mn, "tbnz") == 0)
		nz = 1;
	else
		return 1;
	n = split_commas(op, fields, 3);
	if (n != 3) {
		set_errf1s(err, errcap, "bad operands for %s", mn);
		return -1;
	}
	if (parse_reg(fields[0], &rt, &width, &is_sp, &is_zr) < 0 ||
	    is_sp) {
		set_errf1s(err, errcap, "bad register: %s", fields[0]);
		return -1;
	}
	if (parse_uimm(fields[1], &bit) < 0) {
		set_err(err, errcap, "bad bit immediate");
		return -1;
	}
	if (resolve_target(resolve, resolve_arg, fields[2], &target,
	    err, errcap) < 0)
		return -1;
	return enc_tbz(addr, target, width == 64, (unsigned)bit, nz,
	    rt, wp, err, errcap);
}

static int
parse_addsub_imm_operand(const char *s, uint64_t *vp,
    char *err, size_t errcap)
{
	if (parse_uimm(s, vp) < 0) {
		set_err(err, errcap, "bad immediate");
		return -1;
	}
	return 0;
}

static int
do_add_sub(const char *mn, const char *op, uint32_t *wp,
    char *err, size_t errcap)
{
	int op_sub;
	char fields[3][128];
	int n;
	unsigned rd, rn;
	int wd, wn;
	int is_sp_d, is_zr_d, is_sp_n, is_zr_n;
	uint64_t imm;

	if (strcmp(mn, "add") == 0)
		op_sub = 0;
	else if (strcmp(mn, "sub") == 0)
		op_sub = 1;
	else
		return 1;
	n = split_commas(op, fields, 3);
	if (n != 3) {
		set_errf1s(err, errcap, "bad operands for %s", mn);
		return -1;
	}
	if (parse_reg(fields[0], &rd, &wd, &is_sp_d, &is_zr_d) < 0 ||
	    is_zr_d) {
		set_errf1s(err, errcap, "bad register: %s", fields[0]);
		return -1;
	}
	if (parse_reg(fields[1], &rn, &wn, &is_sp_n, &is_zr_n) < 0 ||
	    is_zr_n) {
		set_errf1s(err, errcap, "bad register: %s", fields[1]);
		return -1;
	}
	if (wd != wn) {
		set_errf1s(err, errcap, "register width mismatch in %s", mn);
		return -1;
	}
	if (parse_addsub_imm_operand(fields[2], &imm, err, errcap) < 0)
		return -1;
	return enc_addsub_imm(wd == 64, op_sub, 0, imm, rn, rd, wp,
	    err, errcap);
}

static int
do_cmp(const char *mn, const char *op, uint32_t *wp,
    char *err, size_t errcap)
{
	char fields[2][128];
	int n;
	unsigned rn;
	int wn;
	int is_sp, is_zr;
	uint64_t imm;

	if (strcmp(mn, "cmp") != 0)
		return 1;
	n = split_commas(op, fields, 2);
	if (n != 2) {
		set_errf1s(err, errcap, "bad operands for %s", mn);
		return -1;
	}
	if (parse_reg(fields[0], &rn, &wn, &is_sp, &is_zr) < 0 ||
	    is_zr) {
		set_errf1s(err, errcap, "bad register: %s", fields[0]);
		return -1;
	}
	if (parse_addsub_imm_operand(fields[1], &imm, err, errcap) < 0)
		return -1;
	/* cmp = subs xzr/wzr, rn, #imm */
	return enc_addsub_imm(wn == 64, 1, 1, imm, rn, 31, wp,
	    err, errcap);
}

static int
do_mov(const char *mn, const char *op, uint32_t *wp,
    char *err, size_t errcap)
{
	char fields[2][128];
	int n;
	unsigned rd, rn;
	int wd, wn;
	int sp_d, zr_d, sp_n, zr_n;

	if (strcmp(mn, "mov") != 0)
		return 1;
	n = split_commas(op, fields, 2);
	if (n != 2) {
		set_errf1s(err, errcap, "bad operands for %s", mn);
		return -1;
	}
	if (parse_reg(fields[0], &rd, &wd, &sp_d, &zr_d) < 0 || zr_d) {
		set_errf1s(err, errcap, "bad register: %s", fields[0]);
		return -1;
	}
	if (parse_reg(fields[1], &rn, &wn, &sp_n, &zr_n) < 0 || zr_n) {
		set_errf1s(err, errcap, "bad register: %s", fields[1]);
		return -1;
	}
	if (wd != 64 || wn != 64) {
		set_err(err, errcap,
		    "mov: only 64-bit SP forms are supported");
		return -1;
	}
	if (!sp_d && !sp_n) {
		set_err(err, errcap,
		    "mov: only mov xD,sp / mov sp,xN are supported");
		return -1;
	}
	/* add rd, rn, #0 with sf=1 */
	return enc_addsub_imm(1, 0, 0, 0, rn, rd, wp, err, errcap);
}

/* --- public entry points -------------------------------------- */

int
zaarch64_assemble_one(zaddr_t addr, const char *line,
    uint8_t *buf, size_t buflen, size_t *lenp,
    zarch_resolve_fn resolve, void *resolve_arg,
    char *err, size_t errcap)
{
	char mn[16];
	char op[256];
	uint32_t w;
	int r;

	if (err != NULL && errcap > 0)
		err[0] = 0;
	if (line == NULL || buf == NULL) {
		set_err(err, errcap, "internal: null arg");
		return -1;
	}
	if (buflen < AARCH64_INSN_BYTES) {
		set_err(err, errcap, "output buffer too small");
		return -1;
	}
	if (split_mn_op(line, mn, sizeof(mn), op, sizeof(op)) < 0) {
		set_err(err, errcap, "instruction too long");
		return -1;
	}
	if (mn[0] == 0) {
		set_err(err, errcap, "missing instruction");
		return -1;
	}

	w = 0;
	r = do_zero_op(mn, op, &w, err, errcap);
	if (r <= 0) goto done;
	r = do_ret_xn(mn, op, &w, err, errcap);
	if (r <= 0) goto done;
	r = do_brk_svc(mn, op, &w, err, errcap);
	if (r <= 0) goto done;
	r = do_br_blr(mn, op, &w, err, errcap);
	if (r <= 0) goto done;
	r = do_b_bl(mn, op, addr, resolve, resolve_arg, &w, err, errcap);
	if (r <= 0) goto done;
	r = do_bcond(mn, op, addr, resolve, resolve_arg, &w, err, errcap);
	if (r <= 0) goto done;
	r = do_cbz(mn, op, addr, resolve, resolve_arg, &w, err, errcap);
	if (r <= 0) goto done;
	r = do_tbz(mn, op, addr, resolve, resolve_arg, &w, err, errcap);
	if (r <= 0) goto done;
	r = do_add_sub(mn, op, &w, err, errcap);
	if (r <= 0) goto done;
	r = do_cmp(mn, op, &w, err, errcap);
	if (r <= 0) goto done;
	r = do_mov(mn, op, &w, err, errcap);
	if (r <= 0) goto done;

	set_errf1s(err, errcap, "unknown instruction: %s", mn);
	return -1;

done:
	if (r < 0)
		return -1;
	put32le(buf, w);
	if (lenp != NULL)
		*lenp = AARCH64_INSN_BYTES;
	return 0;
}

int
zaarch64_assemble_patch(zaddr_t addr, size_t patch_len, const char *line,
    uint8_t *buf, size_t buflen, size_t *lenp,
    zarch_resolve_fn resolve, void *resolve_arg,
    char *err, size_t errcap)
{
	size_t one_len;
	size_t off;

	if (err != NULL && errcap > 0)
		err[0] = 0;
	if (buf == NULL) {
		set_err(err, errcap, "bad patch buffer");
		return -1;
	}
	if (patch_len < AARCH64_INSN_BYTES) {
		set_err(err, errcap,
		    "AArch64 patch length must be at least 4 bytes");
		return -1;
	}
	if ((patch_len % AARCH64_INSN_BYTES) != 0) {
		set_err(err, errcap,
		    "AArch64 patch length must be a multiple of 4");
		return -1;
	}
	if (patch_len > buflen) {
		set_err(err, errcap, "output buffer too small");
		return -1;
	}

	one_len = 0;
	if (zaarch64_assemble_one(addr, line, buf, buflen, &one_len,
	    resolve, resolve_arg, err, errcap) < 0)
		return -1;
	if (one_len != AARCH64_INSN_BYTES) {
		set_err(err, errcap,
		    "internal: unexpected aarch64 instruction length");
		return -1;
	}
	for (off = AARCH64_INSN_BYTES; off < patch_len;
	    off += AARCH64_INSN_BYTES) {
		put32le(buf + off, AARCH64_NOP_WORD);
	}
	if (lenp != NULL)
		*lenp = patch_len;
	return 0;
}
