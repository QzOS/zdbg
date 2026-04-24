/*
 * zdbg_arch.h - architecture identification and x86-64 constants.
 */

#ifndef ZDBG_ARCH_H
#define ZDBG_ARCH_H

enum zarch {
	ZARCH_NONE = 0,
	ZARCH_X86_64
};

/* x86-64 single byte instruction constants used by the tiny
 * patch encoder. */
#define ZDBG_X86_INT3 0xcc
#define ZDBG_X86_NOP  0x90
#define ZDBG_X86_RET  0xc3

#endif /* ZDBG_ARCH_H */
