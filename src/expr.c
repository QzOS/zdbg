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
parse_term(const char **pp, const struct zregs *regs, uint64_t *out)
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
	if (regs != NULL && zregs_get_by_name(regs, buf, &v) == 0) {
		*out = v;
		*pp = p;
		return 0;
	}
	(void)base;
	return -1;
}

int
zexpr_eval(const char *s, const struct zregs *regs, zaddr_t *out)
{
	const char *p;
	uint64_t lhs = 0;
	uint64_t rhs = 0;
	char op = 0;

	if (s == NULL || out == NULL)
		return -1;
	p = s;

	if (parse_term(&p, regs, &lhs) < 0)
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

	if (parse_term(&p, regs, &rhs) < 0)
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
parse_term_maps(const char **pp, const struct zregs *regs,
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
	if (regs != NULL && zregs_get_by_name(regs, buf, &v) == 0) {
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
zexpr_eval_maps(const char *s, const struct zregs *regs,
    const struct zmap_table *maps, zaddr_t *out)
{
	const char *p;
	uint64_t lhs = 0;
	uint64_t rhs = 0;
	char op = 0;

	if (s == NULL || out == NULL)
		return -1;
	if (maps == NULL)
		return zexpr_eval(s, regs, out);

	p = s;
	if (parse_term_maps(&p, regs, maps, &lhs) < 0)
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

	if (parse_term_maps(&p, regs, maps, &rhs) < 0)
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
