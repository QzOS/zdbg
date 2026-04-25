/*
 * zdbg_filter.h - shared stop-filter for software/hardware
 * breakpoints and watchpoints.
 *
 * A `struct zstop_filter` records:
 *   - `hits`: total number of recognized zdbg-owned hits
 *     observed at this breakpoint/watchpoint, including hits
 *     suppressed by ignore count or condition.
 *   - `ignore`: remaining number of hits to suppress before the
 *     debugger stops for the user.
 *   - `cond` / `has_cond`: optional textual condition.  The
 *     condition is evaluated by `zcond_eval()` only when ignore
 *     has been consumed.
 *
 * The filter struct itself is pure data; evaluation against a
 * register set / map / symbol table lives in this module too via
 * `zcond_eval()`.  Keeping evaluation here lets unit tests
 * exercise the parser without bringing in `struct zdbg`.
 */

#ifndef ZDBG_FILTER_H
#define ZDBG_FILTER_H

#include "zdbg.h"
#include "zdbg_regs.h"

struct zmap_table;
struct zsym_table;
struct ztarget;

#define ZDBG_FILTER_EXPR_MAX 128
#define ZDBG_FILTER_AUTO_LIMIT 100000

struct zstop_filter {
	uint64_t hits;
	uint64_t ignore;
	int has_cond;
	char cond[ZDBG_FILTER_EXPR_MAX];
};

void zfilter_init(struct zstop_filter *f);
void zfilter_clear(struct zstop_filter *f);

/*
 * Set the condition to a copy of `s`.  Returns 0 on success and
 * -1 if `s` is too long for the fixed buffer.  A NULL or empty
 * `s` clears the condition.
 */
int  zfilter_set_condition(struct zstop_filter *f, const char *s);
void zfilter_clear_condition(struct zstop_filter *f);

void zfilter_set_ignore(struct zstop_filter *f, uint64_t n);
void zfilter_reset_hits(struct zstop_filter *f);

/*
 * Evaluate a tiny condition expression.  Supported forms:
 *
 *     EXPR
 *     EXPR == EXPR
 *     EXPR != EXPR
 *     EXPR <  EXPR
 *     EXPR <= EXPR
 *     EXPR >  EXPR
 *     EXPR >= EXPR
 *
 * Each `EXPR` is resolved through zexpr_eval_value() so the
 * full address-expression vocabulary plus explicit
 * target-memory dereference (`u8/u16/u32/u64/ptr(EXPR)`) is
 * available.  When `t` is NULL deref forms are not supported
 * and EXPR is resolved through zexpr_eval_symbols() instead.
 *
 * On parse/evaluation success returns 0 and stores 1/0 into
 * `*resultp`.  Returns -1 on parse failure or when an operand
 * cannot be resolved (including memory-read failure for a
 * dereference); `*resultp` is left unchanged in that case.
 *
 * No parentheses, no boolean operators, no side effects beyond
 * the explicit memory reads required by the dereference forms.
 */
int  zcond_eval(const char *s, struct ztarget *t,
    const struct zregs *regs, const struct zmap_table *maps,
    const struct zsym_table *syms, int *resultp);

#endif /* ZDBG_FILTER_H */
