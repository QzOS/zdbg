/*
 * zdbg_tinyasm.h - tiny patch encoder.
 *
 * This is not a real assembler.  It supports the very small
 * instruction set that is useful for manual binary patching:
 *
 *     nop, int3, ret
 *     jmp  rel32   jmp8  rel8
 *     jz   rel32   jz8   rel8   (je alias)
 *     jnz  rel32   jnz8  rel8   (jne alias)
 *     call rel32
 *
 * Encoding size is deterministic and chosen by the mnemonic,
 * not by the operand range, so patches are predictable.
 *
 * Branch/call operand evaluation is delegated to a resolver
 * callback so the command layer can plug in zdbg's symbol
 * and value expression evaluator.  No labels, no memory
 * operand syntax, no relocations, no full x86 syntax.
 */

#ifndef ZDBG_TINYASM_H
#define ZDBG_TINYASM_H

#include "zdbg.h"
#include "zdbg_regs.h"

#define ZDBG_TINYASM_MAX 16

struct ztinyasm {
	uint8_t code[ZDBG_TINYASM_MAX];
	size_t len;
};

/*
 * Operand resolver callback.  `expr` is the trimmed operand
 * string (everything after the mnemonic).  Return 0 on success
 * with *out set to the absolute target address, -1 on error.
 */
typedef int (*ztinyasm_resolve_fn)(void *arg, const char *expr,
    zaddr_t *out);

int ztinyasm_assemble(zaddr_t addr, const char *line, struct ztinyasm *out,
    const struct zregs *regs);
int ztinyasm_patch(zaddr_t addr, size_t patch_len, const char *line,
    uint8_t *buf, size_t buflen, size_t *lenp, const struct zregs *regs);

/*
 * Symbol-aware variants.  Both delegate operand evaluation to
 * `resolve(resolve_arg, expr, &target)`.  On error, when `err`
 * is non-NULL, a short human-readable diagnostic is written to
 * `err` (truncated to errcap-1 bytes plus NUL).
 */
int ztinyasm_assemble_ex(zaddr_t addr, const char *line,
    struct ztinyasm *out,
    ztinyasm_resolve_fn resolve, void *resolve_arg,
    char *err, size_t errcap);
int ztinyasm_patch_ex(zaddr_t addr, size_t patch_len, const char *line,
    uint8_t *buf, size_t buflen, size_t *lenp,
    ztinyasm_resolve_fn resolve, void *resolve_arg,
    char *err, size_t errcap);

/*
 * Invert a single jz/jnz (rel8 or rel32) located at buf.
 * On success *usedp receives the instruction length.
 */
int zpatch_invert_jcc(uint8_t *buf, size_t len, size_t *usedp);

#endif /* ZDBG_TINYASM_H */
