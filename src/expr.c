/*
 * expr.c - tiny expression evaluator.
 *
 * Grammar (informal):
 *     expr   := term ( ("+"|"-") term )?
 *     term   := number | register | module
 *     number := "0x" hexdigits
 *             | hexdigits "h"
 *             | "#" decdigits
 *             | hexdigits             (default base = hex)
 *     module := identifier
 *             | "/absolute/path"
 *             | "[name]"
 *             | "map:N"
 *
 * Module resolution only happens when zexpr_eval_maps() is used
 * with a non-NULL map table.  Module tokens may include '/', '.',
 * '-', '_', '[', ']', ':' so basenames and absolute paths work.
 *
 * Whitespace is allowed around operators and ignored elsewhere.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "zdbg_expr.h"
#include "zdbg_maps.h"
#include "zdbg_regfile.h"
#include "zdbg_symbols.h"
#include "zdbg_target.h"

/*
 * Maximum length of an inner expression accepted by the value
 * evaluator.  Large enough to hold any practical
 * register+symbol+offset combination.
 */
#define ZEXPR_VALUE_BUF 256

static int
is_regchar(int c)
{
	return isalnum(c) != 0;
}

static int
hexval(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return 10 + (c - 'a');
	if (c >= 'A' && c <= 'F')
		return 10 + (c - 'A');
	return -1;
}

/*
 * Parse a single term (register or number) from *pp, advance *pp
 * to the character just past it, and return the numeric value.
 * Returns 0 on success, -1 on failure.
 */
static int
parse_term(const char **pp, const struct zreg_file *rf, uint64_t *out)
{
	const char *p = *pp;
	const char *start;
	char buf[64];
	size_t n;
	uint64_t v = 0;
	int base;
	int had_digit = 0;

	/* skip whitespace */
	while (*p == ' ' || *p == '\t')
		p++;
	if (*p == 0)
		return -1;

	/* decimal prefix '#' */
	if (*p == '#') {
		p++;
		while (*p == ' ' || *p == '\t')
			p++;
		if (!isdigit((unsigned char)*p))
			return -1;
		while (isdigit((unsigned char)*p)) {
			v = v * 10 + (uint64_t)(*p - '0');
			p++;
			had_digit = 1;
		}
		if (!had_digit)
			return -1;
		*out = v;
		*pp = p;
		return 0;
	}

	/* 0x hex prefix */
	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
		p += 2;
		if (hexval((unsigned char)*p) < 0)
			return -1;
		while (hexval((unsigned char)*p) >= 0) {
			v = (v << 4) | (uint64_t)hexval((unsigned char)*p);
			p++;
		}
		*out = v;
		*pp = p;
		return 0;
	}

	/* collect an identifier-or-number token */
	start = p;
	while (is_regchar((unsigned char)*p))
		p++;
	n = (size_t)(p - start);
	if (n == 0 || n >= sizeof(buf))
		return -1;
	memcpy(buf, start, n);
	buf[n] = 0;

	/* "h" suffix -> hex */
	base = 16;
	if (n > 1 && (buf[n - 1] == 'h' || buf[n - 1] == 'H')) {
		/* only valid if the rest is all hex digits */
		size_t i;
		int all_hex = 1;
		for (i = 0; i < n - 1; i++) {
			if (hexval((unsigned char)buf[i]) < 0) {
				all_hex = 0;
				break;
			}
		}
		if (all_hex) {
			for (i = 0; i < n - 1; i++) {
				v = (v << 4) |
				    (uint64_t)hexval((unsigned char)buf[i]);
			}
			*out = v;
			*pp = p;
			return 0;
		}
	}

	/* pure hex number? */
	{
		size_t i;
		int all_hex = 1;
		for (i = 0; i < n; i++) {
			if (hexval((unsigned char)buf[i]) < 0) {
				all_hex = 0;
				break;
			}
		}
		if (all_hex) {
			for (i = 0; i < n; i++) {
				v = (v << 4) |
				    (uint64_t)hexval((unsigned char)buf[i]);
			}
			*out = v;
			*pp = p;
			return 0;
		}
	}

	/* register */
	if (rf != NULL && zregfile_get(rf, buf, &v) == 0) {
		*out = v;
		*pp = p;
		return 0;
	}
	(void)base;
	return -1;
}

int
zexpr_eval_rf(const char *s, const struct zreg_file *rf, zaddr_t *out)
{
	const char *p;
	uint64_t lhs = 0;
	uint64_t rhs = 0;
	char op = 0;

	if (s == NULL || out == NULL)
		return -1;
	p = s;

	if (parse_term(&p, rf, &lhs) < 0)
		return -1;

	while (*p == ' ' || *p == '\t')
		p++;
	if (*p == 0) {
		*out = lhs;
		return 0;
	}

	if (*p == '+' || *p == '-') {
		op = *p;
		p++;
	} else {
		return -1;
	}

	if (parse_term(&p, rf, &rhs) < 0)
		return -1;

	while (*p == ' ' || *p == '\t')
		p++;
	if (*p != 0)
		return -1;

	if (op == '+')
		*out = lhs + rhs;
	else
		*out = lhs - rhs;
	return 0;
}

/*
 * Build a temporary x86-64 register file from a legacy
 * `struct zregs` so the legacy zexpr_eval(...) entry points can
 * delegate to the regfile-aware implementation without having
 * to know an architecture id.  Uses the standard x86-64
 * descriptor table because that is what `struct zregs` mirrors.
 */
static int
build_legacy_rf(struct zreg_file *rf, const struct zregs *regs)
{
	if (regs == NULL) {
		zregfile_init(rf, ZARCH_NONE);
		return 0;
	}
	return zregfile_from_zregs(rf, ZARCH_X86_64, regs);
}

int
zexpr_eval(const char *s, const struct zregs *regs, zaddr_t *out)
{
	struct zreg_file rf;

	if (regs == NULL)
		return zexpr_eval_rf(s, NULL, out);
	if (build_legacy_rf(&rf, regs) < 0)
		return -1;
	return zexpr_eval_rf(s, &rf, out);
}

/* --- map-aware evaluator --------------------------------------- */

static int
is_ident_start(int c)
{
	return isalpha(c) || c == '_' || c == '/' || c == '[';
}

static int
is_ident_cont(int c)
{
	if (isalnum(c))
		return 1;
	switch (c) {
	case '.':
	case '/':
	case '_':
	case '[':
	case ']':
	case ':':
		return 1;
	default:
		return 0;
	}
}

/*
 * Classify a '+' or '-' at position p as either part of a module
 * identifier token or as the binary operator.  A sign is treated
 * as part of the identifier when directly followed by another
 * identifier-continuation character that looks alphabetic (so
 * "ld-linux" keeps the '-') and as operator otherwise (so
 * "main-10" treats '-' as an operator).
 */
static int
sign_belongs_to_ident(const char *p)
{
	if (*p != '+' && *p != '-')
		return 0;
	/* char after the sign */
	{
		int c = (unsigned char)p[1];
		if (c == 0 || c == ' ' || c == '\t')
			return 0;
		if (isdigit(c))
			return 0;
		if (c == '#')
			return 0;
		if (isalpha(c) || c == '_' || c == '.' || c == '/' ||
		    c == '[' || c == ']' || c == ':')
			return 1;
		return 0;
	}
}

/*
 * Try to parse a number from a pre-lexed identifier buffer.
 * Returns 0 on success.
 */
static int
token_to_number(const char *buf, size_t n, uint64_t *out)
{
	uint64_t v = 0;
	size_t i;
	int all_hex;

	if (n == 0)
		return -1;

	/* "h" suffix -> hex */
	if (n > 1 && (buf[n - 1] == 'h' || buf[n - 1] == 'H')) {
		all_hex = 1;
		for (i = 0; i < n - 1; i++) {
			if (hexval((unsigned char)buf[i]) < 0) {
				all_hex = 0;
				break;
			}
		}
		if (all_hex) {
			for (i = 0; i < n - 1; i++) {
				v = (v << 4) |
				    (uint64_t)hexval((unsigned char)buf[i]);
			}
			*out = v;
			return 0;
		}
	}

	all_hex = 1;
	for (i = 0; i < n; i++) {
		if (hexval((unsigned char)buf[i]) < 0) {
			all_hex = 0;
			break;
		}
	}
	if (all_hex) {
		for (i = 0; i < n; i++) {
			v = (v << 4) |
			    (uint64_t)hexval((unsigned char)buf[i]);
		}
		*out = v;
		return 0;
	}
	return -1;
}

static int
parse_term_maps(const char **pp, const struct zreg_file *rf,
    const struct zmap_table *maps, uint64_t *out)
{
	const char *p = *pp;
	const char *start;
	char buf[ZDBG_MAP_NAME_MAX];
	size_t n;
	uint64_t v = 0;
	int had_digit = 0;

	while (*p == ' ' || *p == '\t')
		p++;
	if (*p == 0)
		return -1;

	/* '#' decimal prefix */
	if (*p == '#') {
		p++;
		while (*p == ' ' || *p == '\t')
			p++;
		if (!isdigit((unsigned char)*p))
			return -1;
		while (isdigit((unsigned char)*p)) {
			v = v * 10 + (uint64_t)(*p - '0');
			p++;
			had_digit = 1;
		}
		if (!had_digit)
			return -1;
		*out = v;
		*pp = p;
		return 0;
	}

	/* 0x hex prefix */
	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
		p += 2;
		if (hexval((unsigned char)*p) < 0)
			return -1;
		while (hexval((unsigned char)*p) >= 0) {
			v = (v << 4) | (uint64_t)hexval((unsigned char)*p);
			p++;
		}
		*out = v;
		*pp = p;
		return 0;
	}

	/* Read a module/identifier/number token.  Accepts the
	 * identifier character set plus embedded '-'/'+' when the
	 * sign clearly belongs to an identifier (see helper).
	 */
	start = p;
	if (!is_ident_start((unsigned char)*p) && !isdigit((unsigned char)*p))
		return -1;
	p++;
	while (*p) {
		if (is_ident_cont((unsigned char)*p)) {
			p++;
			continue;
		}
		if ((*p == '-' || *p == '+') && sign_belongs_to_ident(p)) {
			p++;
			continue;
		}
		break;
	}
	n = (size_t)(p - start);
	if (n == 0 || n >= sizeof(buf))
		return -1;
	memcpy(buf, start, n);
	buf[n] = 0;

	/* numeric? (default-hex or h-suffix) */
	if (token_to_number(buf, n, &v) == 0) {
		*out = v;
		*pp = p;
		return 0;
	}

	/* register? */
	if (rf != NULL && zregfile_get(rf, buf, &v) == 0) {
		*out = v;
		*pp = p;
		return 0;
	}

	/* module? */
	if (maps != NULL) {
		int amb = 0;
		const struct zmap *m = zmaps_find_module(maps, buf, &amb);
		if (m != NULL) {
			*out = m->start;
			*pp = p;
			return 0;
		}
		if (amb) {
			fprintf(stderr, "ambiguous module name: %s\n", buf);
			return -1;
		}
	}
	return -1;
}

int
zexpr_eval_maps_rf(const char *s, const struct zreg_file *rf,
    const struct zmap_table *maps, zaddr_t *out)
{
	const char *p;
	uint64_t lhs = 0;
	uint64_t rhs = 0;
	char op = 0;

	if (s == NULL || out == NULL)
		return -1;
	if (maps == NULL)
		return zexpr_eval_rf(s, rf, out);

	p = s;
	if (parse_term_maps(&p, rf, maps, &lhs) < 0)
		return -1;

	while (*p == ' ' || *p == '\t')
		p++;
	if (*p == 0) {
		*out = lhs;
		return 0;
	}

	if (*p == '+' || *p == '-') {
		op = *p;
		p++;
	} else {
		return -1;
	}

	if (parse_term_maps(&p, rf, maps, &rhs) < 0)
		return -1;

	while (*p == ' ' || *p == '\t')
		p++;
	if (*p != 0)
		return -1;

	if (op == '+')
		*out = lhs + rhs;
	else
		*out = lhs - rhs;
	return 0;
}

int
zexpr_eval_maps(const char *s, const struct zregs *regs,
    const struct zmap_table *maps, zaddr_t *out)
{
	struct zreg_file rf;

	if (regs == NULL)
		return zexpr_eval_maps_rf(s, NULL, maps, out);
	if (build_legacy_rf(&rf, regs) < 0)
		return -1;
	return zexpr_eval_maps_rf(s, &rf, maps, out);
}

/* --- symbol-aware evaluator ------------------------------------ */

/*
 * Strip optional trailing "+N"/"-N" from s into base and
 * *off/op.  Returns 1 if an offset was found, 0 otherwise,
 * -1 on overflow.  The offset side must be a pure number or
 * register; if it parses as one the split is kept, otherwise
 * the whole expression is returned as the base.
 */
static int
split_off(const char *s, char *base, size_t cap, uint64_t *off, char *op)
{
	const char *p;
	const char *last_sign = NULL;
	size_t n;

	for (p = s; *p; p++) {
		if ((*p == '+' || *p == '-') && p != s)
			last_sign = p;
	}
	if (last_sign == NULL) {
		n = strlen(s);
		if (n >= cap)
			return -1;
		memcpy(base, s, n);
		base[n] = 0;
		*off = 0;
		*op = 0;
		return 0;
	}
	n = (size_t)(last_sign - s);
	if (n >= cap)
		return -1;
	memcpy(base, s, n);
	base[n] = 0;
	*op = *last_sign;
	{
		const char *q = last_sign + 1;
		while (*q == ' ' || *q == '\t')
			q++;
		if (zexpr_eval(q, NULL, off) < 0) {
			n = strlen(s);
			if (n >= cap)
				return -1;
			memcpy(base, s, n);
			base[n] = 0;
			*off = 0;
			*op = 0;
			return 0;
		}
	}
	return 1;
}

int
zexpr_eval_symbols_rf(const char *s, const struct zreg_file *rf,
    const struct zmap_table *maps, const struct zsym_table *syms,
    zaddr_t *out)
{
	char base[ZDBG_SYM_NAME_MAX + ZDBG_SYM_MODULE_MAX + 8];
	uint64_t off = 0;
	char op = 0;
	int has_off;
	zaddr_t v = 0;
	int amb = 0;
	const struct zsym *sym = NULL;
	const char *colon;

	if (s == NULL || out == NULL)
		return -1;

	/*
	 * Fast path: pure number or register (no module, no
	 * symbol).  Doing this first makes numbers like "401000"
	 * not accidentally shadow a symbol named "401000".
	 */
	if (zexpr_eval_rf(s, rf, out) == 0)
		return 0;

	if (syms == NULL)
		return zexpr_eval_maps_rf(s, rf, maps, out);

	has_off = split_off(s, base, sizeof(base), &off, &op);
	if (has_off < 0)
		return -1;

	/* Trim whitespace around base. */
	{
		char *b = base;
		size_t n;
		while (*b == ' ' || *b == '\t')
			b++;
		if (b != base)
			memmove(base, b, strlen(b) + 1);
		n = strlen(base);
		while (n > 0 && (base[n - 1] == ' ' || base[n - 1] == '\t'))
			base[--n] = 0;
	}
	if (base[0] == 0)
		return -1;

	colon = strchr(base, ':');

	/*
	 * "name+N" / "name-N" with no colon: preserve legacy
	 * mapping-relative semantics.  If the LHS happens to be
	 * a mapping, the whole expression already resolved via
	 * zexpr_eval_maps_rf() before symbol lookup.  We special-case
	 * "map:N" which contains a colon but is a map token - it
	 * will be handled here and its strchr hit points inside
	 * "map:"; fall through to the colon branch only for
	 * module:symbol.
	 */
	if (has_off && colon == NULL) {
		if (zexpr_eval_maps_rf(s, rf, maps, out) == 0)
			return 0;
		/* fall through: try symbol+offset */
	}

	if (colon != NULL) {
		/* "map:N" is a map token; try map-eval first. */
		if (zexpr_eval_maps_rf(s, rf, maps, out) == 0)
			return 0;
		{
			int srv = zsyms_resolve(syms, maps, base, &v);
			if (srv == 0) {
				if (op == '+')
					*out = (zaddr_t)(v + off);
				else if (op == '-')
					*out = (zaddr_t)(v - off);
				else
					*out = v;
				return 0;
			}
			if (srv == -2)
				fprintf(stderr,
				    "ambiguous symbol: %s\n", base);
		}
		return -1;
	}

	/* Exact unqualified symbol lookup (precedence > module). */
	sym = zsyms_find_exact(syms, base, &amb);
	if (sym != NULL) {
		v = sym->addr;
		if (op == '+')
			*out = (zaddr_t)(v + off);
		else if (op == '-')
			*out = (zaddr_t)(v - off);
		else
			*out = v;
		return 0;
	}
	if (amb) {
		fprintf(stderr, "ambiguous symbol: %s\n", base);
		return -1;
	}

	/* Fall back to mapping base lookup (e.g. plain "libc"). */
	return zexpr_eval_maps_rf(s, rf, maps, out);
}

int
zexpr_eval_symbols(const char *s, const struct zregs *regs,
    const struct zmap_table *maps, const struct zsym_table *syms,
    zaddr_t *out)
{
	struct zreg_file rf;

	if (regs == NULL)
		return zexpr_eval_symbols_rf(s, NULL, maps, syms, out);
	if (build_legacy_rf(&rf, regs) < 0)
		return -1;
	return zexpr_eval_symbols_rf(s, &rf, maps, syms, out);
}

/* --- value evaluator (explicit target-memory dereference) ------ */

/*
 * Trim leading and trailing whitespace from [s, s+n) into a
 * caller-supplied buffer `dst` of capacity `cap`.  Returns 0 on
 * success and -1 if the trimmed string would not fit (or is
 * empty).
 */
static int
trim_to(const char *s, size_t n, char *dst, size_t cap)
{
	size_t i = 0;

	while (i < n && (s[i] == ' ' || s[i] == '\t'))
		i++;
	while (n > i && (s[n - 1] == ' ' || s[n - 1] == '\t'))
		n--;
	if (n <= i)
		return -1;
	if ((n - i) >= cap)
		return -1;
	memcpy(dst, s + i, n - i);
	dst[n - i] = 0;
	return 0;
}

/*
 * Recognise a deref keyword starting at p.  Returns the byte
 * width (1/2/4/8), writes 1 to *signp for signed forms, and
 * advances *pp past the keyword and any whitespace up to '('.
 * Returns 0 if no keyword matches.
 */
static int
match_deref_kw(const char **pp, int *signp)
{
	const char *p = *pp;
	struct kw {
		const char *name;
		int width;
		int sign;
	};
	static const struct kw table[] = {
		{ "u8",  1, 0 },
		{ "u16", 2, 0 },
		{ "u32", 4, 0 },
		{ "u64", 8, 0 },
		{ "ptr", 8, 0 },
		{ "poi", 8, 0 },
		{ "s8",  1, 1 },
		{ "s16", 2, 1 },
		{ "s32", 4, 1 },
		{ NULL,  0, 0 }
	};
	int i;

	for (i = 0; table[i].name != NULL; i++) {
		size_t kl = strlen(table[i].name);
		if (strncmp(p, table[i].name, kl) != 0)
			continue;
		{
			const char *q = p + kl;
			while (*q == ' ' || *q == '\t')
				q++;
			if (*q != '(')
				continue;
			*pp = q;	/* points at '(' */
			*signp = table[i].sign;
			return table[i].width;
		}
	}
	return 0;
}

/*
 * Find the offset of the matching ')' for the '(' at *p (which
 * must point at '(').  Tracks nested parens.  Returns the
 * offset relative to *p of the matching ')' on success and -1
 * if the parens do not balance.
 */
static int
find_matching_paren(const char *p)
{
	int depth = 0;
	int i = 0;

	if (p[0] != '(')
		return -1;
	for (;;) {
		char c = p[i];
		if (c == 0)
			return -1;
		if (c == '(')
			depth++;
		else if (c == ')') {
			depth--;
			if (depth == 0)
				return i;
		}
		i++;
	}
}

/*
 * Find the first top-level '+' or '-' in `s` that is outside
 * any parenthesised group and that is not part of an identifier
 * (sign-belongs-to-ident from the existing parser).  The first
 * character is never considered (so a leading sign is treated
 * as part of the term).  Returns NULL when no such operator
 * exists.
 */
static const char *
find_top_arith_op(const char *s)
{
	int depth = 0;
	const char *p;

	for (p = s; *p; p++) {
		if (*p == '(') {
			depth++;
			continue;
		}
		if (*p == ')') {
			if (depth > 0)
				depth--;
			continue;
		}
		if (depth != 0)
			continue;
		if (p == s)
			continue;
		if (*p != '+' && *p != '-')
			continue;
		if (sign_belongs_to_ident(p))
			continue;
		return p;
	}
	return NULL;
}

/*
 * Decode `n` little-endian bytes from `b` into an unsigned
 * 64-bit value.  `n` is 1, 2, 4 or 8.
 */
static uint64_t
decode_le(const uint8_t *b, int n)
{
	uint64_t v = 0;
	int i;

	for (i = 0; i < n; i++)
		v |= (uint64_t)b[i] << (i * 8);
	return v;
}

/*
 * Sign-extend `v` from `width` bytes to a signed 64-bit value
 * and return as uint64_t bits.
 */
static uint64_t
sign_extend(uint64_t v, int width)
{
	uint64_t mask;
	uint64_t sign;

	if (width >= 8)
		return v;
	mask = ((uint64_t)1 << (width * 8)) - 1;
	sign = (uint64_t)1 << (width * 8 - 1);
	v &= mask;
	if (v & sign)
		v |= ~mask;
	return v;
}

static int eval_value_term(const char *s, size_t len,
    const struct zreg_file *rf, const struct zmap_table *maps,
    const struct zsym_table *syms,
    zexpr_readmem_fn readfn, void *readarg, zaddr_t *out);

/*
 * Evaluate a single value term.  A term is either a deref
 * `FUNC(EXPR)` (with optional whitespace before/after the
 * parens) or a plain expression accepted by zexpr_eval_symbols_rf.
 */
static int
eval_value_term(const char *s, size_t len, const struct zreg_file *rf,
    const struct zmap_table *maps, const struct zsym_table *syms,
    zexpr_readmem_fn readfn, void *readarg, zaddr_t *out)
{
	char buf[ZEXPR_VALUE_BUF];
	const char *p;
	const char *kp;
	int width;
	int is_signed = 0;
	int paren_off;
	zaddr_t addr = 0;
	uint8_t mb[8];

	if (trim_to(s, len, buf, sizeof(buf)) < 0)
		return -1;

	p = buf;
	kp = p;
	width = match_deref_kw(&kp, &is_signed);
	if (width != 0) {
		/* Must be FUNC( ... ) at the start, with only optional
		 * trailing whitespace after the closing paren. */
		paren_off = find_matching_paren(kp);
		if (paren_off < 0)
			return -1;
		{
			const char *tail = kp + paren_off + 1;
			while (*tail == ' ' || *tail == '\t')
				tail++;
			if (*tail != 0)
				return -1;
		}
		/* Inner expression. */
		if (eval_value_term(kp + 1, (size_t)(paren_off - 1),
		    rf, maps, syms, readfn, readarg, &addr) < 0)
			return -1;
		if (readfn == NULL)
			return -1;
		if (readfn(readarg, addr, mb, (size_t)width) < 0) {
			fprintf(stderr,
			    "cannot read u%d at %016llx\n",
			    width * 8, (unsigned long long)addr);
			return -1;
		}
		{
			uint64_t v = decode_le(mb, width);
			if (is_signed)
				v = sign_extend(v, width);
			*out = (zaddr_t)v;
		}
		return 0;
	}

	/* Not a deref: defer to the symbol-aware evaluator. */
	return zexpr_eval_symbols_rf(buf, rf, maps, syms, out);
}

int
zexpr_eval_value_cb_rf(const char *s, const struct zreg_file *rf,
    const struct zmap_table *maps, const struct zsym_table *syms,
    zexpr_readmem_fn readfn, void *readarg, zaddr_t *out)
{
	const char *op;
	zaddr_t lhs = 0;
	zaddr_t rhs = 0;

	if (s == NULL || out == NULL)
		return -1;

	/*
	 * Fast path: if the existing symbol-aware evaluator can
	 * handle it (numbers, registers, symbols, modules, single
	 * +/-), use that result directly.  This preserves all
	 * legacy semantics including `main+1000` mapping-relative.
	 */
	if (zexpr_eval_symbols_rf(s, rf, maps, syms, out) == 0)
		return 0;

	/* Slow path: at least one deref is involved. */
	op = find_top_arith_op(s);
	if (op == NULL)
		return eval_value_term(s, strlen(s), rf, maps, syms,
		    readfn, readarg, out);

	if (eval_value_term(s, (size_t)(op - s), rf, maps, syms,
	    readfn, readarg, &lhs) < 0)
		return -1;
	if (eval_value_term(op + 1, strlen(op + 1), rf, maps, syms,
	    readfn, readarg, &rhs) < 0)
		return -1;
	if (*op == '+')
		*out = (zaddr_t)((uint64_t)lhs + (uint64_t)rhs);
	else
		*out = (zaddr_t)((uint64_t)lhs - (uint64_t)rhs);
	return 0;
}

int
zexpr_eval_value_cb(const char *s, const struct zregs *regs,
    const struct zmap_table *maps, const struct zsym_table *syms,
    zexpr_readmem_fn readfn, void *readarg, zaddr_t *out)
{
	struct zreg_file rf;

	if (regs == NULL)
		return zexpr_eval_value_cb_rf(s, NULL, maps, syms,
		    readfn, readarg, out);
	if (build_legacy_rf(&rf, regs) < 0)
		return -1;
	return zexpr_eval_value_cb_rf(s, &rf, maps, syms,
	    readfn, readarg, out);
}

/*
 * ztarget-backed adapter for the read callback.  Defined here
 * so the value evaluator only depends on a forward-declared
 * struct ztarget at the API boundary.
 */
static int
target_readmem_cb(void *arg, zaddr_t addr, void *buf, size_t len)
{
	struct ztarget *t = (struct ztarget *)arg;

	return ztarget_read(t, addr, buf, len);
}

int
zexpr_eval_value(const char *s, struct ztarget *t,
    const struct zregs *regs, const struct zmap_table *maps,
    const struct zsym_table *syms, zaddr_t *out)
{
	if (s == NULL || out == NULL)
		return -1;
	return zexpr_eval_value_cb(s, regs, maps, syms,
	    t != NULL ? target_readmem_cb : NULL,
	    (void *)t, out);
}

int
zexpr_eval_value_rf(const char *s, struct ztarget *t,
    const struct zreg_file *rf, const struct zmap_table *maps,
    const struct zsym_table *syms, zaddr_t *out)
{
	if (s == NULL || out == NULL)
		return -1;
	return zexpr_eval_value_cb_rf(s, rf, maps, syms,
	    t != NULL ? target_readmem_cb : NULL,
	    (void *)t, out);
}
