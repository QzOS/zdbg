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

int zexpr_eval(const char *s, const struct zregs *regs, zaddr_t *out);

#endif /* ZDBG_EXPR_H */
