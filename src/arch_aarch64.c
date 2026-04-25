/*
 * arch_aarch64.c - AArch64 target architecture ops table.
 *
 * Wraps the phase-1 AArch64 disassembler (arch_aarch64_dis.c)
 * and tiny patch encoder (arch_aarch64_asm.c) behind the generic
 * `struct zarch_ops` interface, and supplies the breakpoint
 * instruction bytes plus PC-after-trap policy.  Conditional-jump
 * inversion, register accessors, and frame-pointer backtrace
 * remain unsupported and return -1; the register-print/get/set
 * hooks are present but report unsupported cleanly.
 *
 * The breakpoint instruction is the canonical `BRK #0` little
 * endian encoding, length 4.  The PC-after-trap correction is the
 * identity: AArch64 reports the BRK address itself when the trap
 * fires, so generic breakpoint code must not reuse the x86 -1
 * adjustment.
 */

#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "zdbg_arch.h"
#include "zdbg_arch_aarch64.h"

/* BRK #0: 0xd4200000, encoded little-endian. */
static const uint8_t aarch64_brk[4] = { 0x00, 0x00, 0x20, 0xd4 };

static int
aarch64_invert_jcc(uint8_t *buf, size_t len, size_t *usedp)
{
	(void)buf;
	(void)len;
	(void)usedp;
	return -1;
}

static int
aarch64_unsupported_get(const struct zregs *regs, zaddr_t *out)
{
	(void)regs;
	(void)out;
	return -1;
}

static int
aarch64_unsupported_set(struct zregs *regs, zaddr_t pc)
{
	(void)regs;
	(void)pc;
	return -1;
}

static zaddr_t
aarch64_breakpoint_pc_after_trap(zaddr_t pc)
{
	/* AArch64 reports the BRK PC itself; no rewind. */
	return pc;
}

static void
aarch64_regs_print(const struct zregs *regs)
{
	(void)regs;
	printf("registers unsupported for architecture aarch64\n");
}

static int
aarch64_regs_get_by_name(const struct zregs *regs, const char *name,
    uint64_t *vp)
{
	(void)regs;
	(void)name;
	(void)vp;
	return -1;
}

static int
aarch64_regs_set_by_name(struct zregs *regs, const char *name, uint64_t v)
{
	(void)regs;
	(void)name;
	(void)v;
	return -1;
}

static int
aarch64_backtrace_fp(struct ztarget *target, const struct zregs *regs,
    const struct zmap_table *maps, int max_frames,
    void (*emit)(void *arg, int idx, zaddr_t addr), void *arg)
{
	(void)target;
	(void)regs;
	(void)maps;
	(void)max_frames;
	(void)emit;
	(void)arg;
	return -1;
}

static const struct zarch_ops aarch64_ops = {
	.arch = ZARCH_AARCH64,
	.name = "aarch64",
	.breakpoint_bytes = aarch64_brk,
	.breakpoint_len = sizeof(aarch64_brk),
	.decode_one = zaarch64_decode_one,
	.fallthrough = zaarch64_fallthrough,
	.assemble_one = zaarch64_assemble_one,
	.assemble_patch = zaarch64_assemble_patch,
	.invert_jcc = aarch64_invert_jcc,
	.get_pc = aarch64_unsupported_get,
	.set_pc = aarch64_unsupported_set,
	.get_sp = aarch64_unsupported_get,
	.get_fp = aarch64_unsupported_get,
	.pc_reg_name = "pc",
	.sp_reg_name = "sp",
	.fp_reg_name = "x29",
	.breakpoint_pc_after_trap = aarch64_breakpoint_pc_after_trap,
	.regs_print = aarch64_regs_print,
	.regs_get_by_name = aarch64_regs_get_by_name,
	.regs_set_by_name = aarch64_regs_set_by_name,
	.backtrace_fp = aarch64_backtrace_fp
};

const struct zarch_ops *
zarch_aarch64(void)
{
	return &aarch64_ops;
}
