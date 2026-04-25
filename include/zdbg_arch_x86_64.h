/*
 * zdbg_arch_x86_64.h - x86-64 private constants.
 *
 * These bytes are intentionally not in the generic zdbg_arch.h.
 * Only the x86-64 architecture implementation and the legacy
 * tinyasm/tinydis modules should include this header.
 */

#ifndef ZDBG_ARCH_X86_64_H
#define ZDBG_ARCH_X86_64_H

/* Single-byte instructions used by the tiny patch encoder and the
 * software-breakpoint installer. */
#define ZDBG_X86_INT3 0xcc
#define ZDBG_X86_NOP  0x90
#define ZDBG_X86_RET  0xc3

#endif /* ZDBG_ARCH_X86_64_H */
