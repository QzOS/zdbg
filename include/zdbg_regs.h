/*
 * zdbg_regs.h - portable x86-64 register snapshot.
 */

#ifndef ZDBG_REGS_H
#define ZDBG_REGS_H

#include "zdbg.h"

struct zregs {
	uint64_t rax;
	uint64_t rbx;
	uint64_t rcx;
	uint64_t rdx;
	uint64_t rsi;
	uint64_t rdi;
	uint64_t rbp;
	uint64_t rsp;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;
	uint64_t rip;
	uint64_t rflags;
};

void zregs_clear(struct zregs *r);
void zregs_print(const struct zregs *r);
int  zregs_get_by_name(const struct zregs *r, const char *name, uint64_t *vp);
int  zregs_set_by_name(struct zregs *r, const char *name, uint64_t v);

#endif /* ZDBG_REGS_H */
