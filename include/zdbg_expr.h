/*
 * zdbg_expr.h - tiny expression evaluator.
 *
 * Parses:
 *     hexadecimal number   (default base)
 *     0x prefix            hexadecimal
 *     h suffix             hexadecimal
 *     # prefix             decimal
 *     register name        case-insensitive, uses regs if non-NULL
 *     reg +/- number       single optional offset
 *
 * No parentheses.  No multiplication.  No symbols.  No module
 * names.  The parser is deliberately tiny.
 */

#ifndef ZDBG_EXPR_H
#define ZDBG_EXPR_H

#include "zdbg.h"
#include "zdbg_regs.h"

struct zmap_table;

int zexpr_eval(const char *s, const struct zregs *regs, zaddr_t *out);

/*
 * Like zexpr_eval() but additionally resolves module-relative
 * expressions:
 *
 *     main                      selected main mapping start
 *     main+N                    selected main mapping start + N
 *     basename[+|-]N            matching file-backed mapping
 *     /absolute/path[+|-]N      exact path match
 *     [stack]+N                 bracketed special maps
 *     map:I[+|-]N               the Ith entry
 *
 * If maps is NULL, behaves exactly like zexpr_eval().
 */
int zexpr_eval_maps(const char *s, const struct zregs *regs,
    const struct zmap_table *maps, zaddr_t *out);

#endif /* ZDBG_EXPR_H */
