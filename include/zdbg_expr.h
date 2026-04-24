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
struct zsym_table;

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

/*
 * Full expression evaluator: numbers, registers, map-relative
 * and ELF symbol names (unqualified and "module:symbol").  If
 * either maps or syms is NULL, the corresponding feature is
 * skipped.
 *
 * Resolution precedence:
 *   1. numeric / register
 *   2. if token contains ':'   -> qualified symbol lookup
 *   3. if expression has a + or - and the LHS matches a
 *      mapping name, use mapping-relative semantics
 *      (preserves "main+1000" and "libc+18a70")
 *   4. exact symbol name
 *   5. mapping base lookup
 */
int zexpr_eval_symbols(const char *s, const struct zregs *regs,
    const struct zmap_table *maps, const struct zsym_table *syms,
    zaddr_t *out);

#endif /* ZDBG_EXPR_H */
