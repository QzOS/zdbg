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
struct ztarget;

/*
 * Memory-read callback used by the value evaluator.  Returns 0
 * on success and -1 on failure.  `arg` is the opaque pointer
 * passed alongside the callback.
 */
typedef int (*zexpr_readmem_fn)(void *arg, zaddr_t addr, void *buf,
    size_t len);

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

/*
 * Value evaluator: extends zexpr_eval_symbols() with explicit
 * target-memory dereference forms
 *
 *     u8(EXPR), u16(EXPR), u32(EXPR), u64(EXPR), ptr(EXPR)
 *     s8(EXPR), s16(EXPR), s32(EXPR)
 *     poi(EXPR)                             alias for ptr
 *
 * Each FUNC(EXPR) reads bytes from the target address EXPR
 * (decoded little-endian) and produces an unsigned 64-bit
 * value (signed forms sign-extend to 64 bits).  EXPR itself
 * uses the full address-expression vocabulary and may contain
 * another dereference.  Whitespace is allowed around the
 * parentheses and operators.  One outer `+`/`-` arithmetic
 * step is supported between value terms.
 *
 * No general parentheses, no operator precedence beyond the
 * tiny existing grammar, no casts, no struct/array/field
 * access, no boolean operators, no side effects.
 *
 * The _cb variant takes an explicit memory-read callback so
 * unit tests can drive the evaluator without a live target.
 * The non-_cb wrapper uses ztarget_read() on `t` and is a
 * no-op (-1) if `t` is NULL.
 *
 * Returns 0 on success and -1 on parse error or read failure.
 */
int zexpr_eval_value_cb(const char *s, const struct zregs *regs,
    const struct zmap_table *maps, const struct zsym_table *syms,
    zexpr_readmem_fn readfn, void *readarg, zaddr_t *out);

int zexpr_eval_value(const char *s, struct ztarget *t,
    const struct zregs *regs, const struct zmap_table *maps,
    const struct zsym_table *syms, zaddr_t *out);

#endif /* ZDBG_EXPR_H */
