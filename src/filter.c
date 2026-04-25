/*
 * filter.c - shared breakpoint/watchpoint stop filter and tiny
 * condition evaluator.
 *
 * Filter state is pure data; the central post-wait path in
 * cmd.c is responsible for incrementing `hits`, consuming
 * `ignore`, and calling zcond_eval() when a condition is set.
 *
 * The condition evaluator parses a single operator and two
 * sub-expressions delegated to zexpr_eval_symbols().  No
 * parentheses, no boolean operators, no dereferences, no side
 * effects.  Two-character operators (<=, >=, ==, !=) are tested
 * before single-character < / >, and operators are searched
 * left-to-right.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "zdbg_filter.h"
#include "zdbg_expr.h"

void
zfilter_init(struct zstop_filter *f)
{
	if (f == NULL)
		return;
	memset(f, 0, sizeof(*f));
}

void
zfilter_clear(struct zstop_filter *f)
{
	if (f == NULL)
		return;
	memset(f, 0, sizeof(*f));
}

int
zfilter_set_condition(struct zstop_filter *f, const char *s)
{
	size_t n;

	if (f == NULL)
		return -1;
	if (s == NULL || *s == 0) {
		zfilter_clear_condition(f);
		return 0;
	}
	n = strlen(s);
	if (n >= sizeof(f->cond))
		return -1;
	memcpy(f->cond, s, n);
	f->cond[n] = 0;
	f->has_cond = 1;
	return 0;
}

void
zfilter_clear_condition(struct zstop_filter *f)
{
	if (f == NULL)
		return;
	f->has_cond = 0;
	f->cond[0] = 0;
}

void
zfilter_set_ignore(struct zstop_filter *f, uint64_t n)
{
	if (f == NULL)
		return;
	f->ignore = n;
}

void
zfilter_reset_hits(struct zstop_filter *f)
{
	if (f == NULL)
		return;
	f->hits = 0;
}

/*
 * Trim leading and trailing ASCII whitespace by adjusting
 * `*pp` and the returned length.  Returns the in-place length
 * with leading whitespace skipped.
 */
static size_t
trim(const char **pp, size_t len)
{
	const char *p;

	if (pp == NULL || *pp == NULL)
		return 0;
	p = *pp;
	while (len > 0 && (*p == ' ' || *p == '\t')) {
		p++;
		len--;
	}
	while (len > 0 &&
	    (p[len - 1] == ' ' || p[len - 1] == '\t'))
		len--;
	*pp = p;
	return len;
}

/*
 * Copy a substring [p, p+len) into a small NUL-terminated buffer
 * `dst` of capacity `cap`.  Returns 0 on success, -1 if the
 * source is empty or does not fit.
 */
static int
copy_operand(const char *p, size_t len, char *dst, size_t cap)
{
	if (p == NULL || dst == NULL || cap == 0)
		return -1;
	if (len == 0 || len >= cap)
		return -1;
	memcpy(dst, p, len);
	dst[len] = 0;
	return 0;
}

/*
 * Find the first comparison operator in `s`.  Operators are
 * searched left-to-right; two-character forms (<=, >=, ==, !=)
 * take precedence over single-character < and >.
 *
 * Returns a pointer to the operator on success and writes the
 * operator length into *oplenp; returns NULL when no operator
 * is found.
 */
static const char *
find_operator(const char *s, int *oplenp)
{
	const char *p;

	if (s == NULL || oplenp == NULL)
		return NULL;
	for (p = s; *p; p++) {
		if (p[0] == '<' && p[1] == '=') {
			*oplenp = 2;
			return p;
		}
		if (p[0] == '>' && p[1] == '=') {
			*oplenp = 2;
			return p;
		}
		if (p[0] == '=' && p[1] == '=') {
			*oplenp = 2;
			return p;
		}
		if (p[0] == '!' && p[1] == '=') {
			*oplenp = 2;
			return p;
		}
		if (p[0] == '<' || p[0] == '>') {
			*oplenp = 1;
			return p;
		}
	}
	return NULL;
}

int
zcond_eval(const char *s, const struct zregs *regs,
    const struct zmap_table *maps, const struct zsym_table *syms,
    int *resultp)
{
	const char *trimmed;
	size_t tlen;
	const char *op;
	int oplen = 0;
	char tmp[ZDBG_FILTER_EXPR_MAX];
	char lhsbuf[ZDBG_FILTER_EXPR_MAX];
	char rhsbuf[ZDBG_FILTER_EXPR_MAX];
	const char *lp;
	const char *rp;
	size_t llen;
	size_t rlen;
	zaddr_t lhs = 0;
	zaddr_t rhs = 0;
	int rc;

	if (s == NULL || resultp == NULL)
		return -1;

	trimmed = s;
	tlen = strlen(s);
	tlen = trim(&trimmed, tlen);
	if (tlen == 0)
		return -1;

	/*
	 * Stash a NUL-terminated, trimmed copy in `tmp` so the
	 * scan and the operand pointers reference a stable buffer
	 * that we never overwrite.
	 */
	if (tlen >= sizeof(tmp))
		return -1;
	memcpy(tmp, trimmed, tlen);
	tmp[tlen] = 0;

	op = find_operator(tmp, &oplen);
	if (op == NULL) {
		/* bare expression: nonzero == true */
		if (zexpr_eval_symbols(tmp, regs, maps, syms, &lhs) < 0)
			return -1;
		*resultp = (lhs != 0) ? 1 : 0;
		return 0;
	}

	lp = tmp;
	llen = (size_t)(op - tmp);
	llen = trim(&lp, llen);
	rp = op + oplen;
	rlen = strlen(rp);
	rlen = trim(&rp, rlen);

	if (copy_operand(lp, llen, lhsbuf, sizeof(lhsbuf)) < 0)
		return -1;
	if (copy_operand(rp, rlen, rhsbuf, sizeof(rhsbuf)) < 0)
		return -1;

	if (zexpr_eval_symbols(lhsbuf, regs, maps, syms, &lhs) < 0)
		return -1;
	if (zexpr_eval_symbols(rhsbuf, regs, maps, syms, &rhs) < 0)
		return -1;

	rc = 0;
	if (oplen == 2) {
		if (op[0] == '<' && op[1] == '=')
			rc = ((uint64_t)lhs <= (uint64_t)rhs) ? 1 : 0;
		else if (op[0] == '>' && op[1] == '=')
			rc = ((uint64_t)lhs >= (uint64_t)rhs) ? 1 : 0;
		else if (op[0] == '=' && op[1] == '=')
			rc = ((uint64_t)lhs == (uint64_t)rhs) ? 1 : 0;
		else if (op[0] == '!' && op[1] == '=')
			rc = ((uint64_t)lhs != (uint64_t)rhs) ? 1 : 0;
		else
			return -1;
	} else if (oplen == 1) {
		if (op[0] == '<')
			rc = ((uint64_t)lhs < (uint64_t)rhs) ? 1 : 0;
		else if (op[0] == '>')
			rc = ((uint64_t)lhs > (uint64_t)rhs) ? 1 : 0;
		else
			return -1;
	} else {
		return -1;
	}

	*resultp = rc;
	return 0;
}
