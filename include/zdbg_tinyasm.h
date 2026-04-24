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
 *
 * Encoding size is deterministic and chosen by the mnemonic,
 * not by the operand range, so patches are predictable.
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

int ztinyasm_assemble(zaddr_t addr, const char *line, struct ztinyasm *out,
    const struct zregs *regs);
int ztinyasm_patch(zaddr_t addr, size_t patch_len, const char *line,
    uint8_t *buf, size_t buflen, size_t *lenp, const struct zregs *regs);

/*
 * Invert a single jz/jnz (rel8 or rel32) located at buf.
 * On success *usedp receives the instruction length.
 */
int zpatch_invert_jcc(uint8_t *buf, size_t len, size_t *usedp);

#endif /* ZDBG_TINYASM_H */
