/*
 * arch_aarch64.c - AArch64 target architecture stub.
 *
 * This stub exists so the debugger core can compile against a
 * non-x86 ops table and prove the architecture boundary holds.
 * It does not implement real AArch64 decoding, assembly, or
 * register access.  Decode/assemble/invert_jcc and the register
 * accessors all return -1 (unsupported).
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

/* BRK #0: 0xd4200000, encoded little-endian. */
static const uint8_t aarch64_brk[4] = { 0x00, 0x00, 0x20, 0xd4 };

static int
aarch64_decode_one(zaddr_t addr, const uint8_t *buf, size_t buflen,
    struct zdecode *out)
{
	(void)addr;
	(void)buf;
	(void)buflen;
	if (out != NULL)
		memset(out, 0, sizeof(*out));
	return -1;
}

static zaddr_t
aarch64_fallthrough(const struct zdecode *d)
{
	if (d == NULL || d->len == 0)
		return 0;
	return d->addr + (zaddr_t)d->len;
}

static int
aarch64_assemble_one(zaddr_t addr, const char *line,
    uint8_t *buf, size_t buflen, size_t *lenp,
    zarch_resolve_fn resolve, void *resolve_arg,
    char *err, size_t errcap)
{
	(void)addr;
	(void)line;
	(void)buf;
	(void)buflen;
	(void)lenp;
	(void)resolve;
	(void)resolve_arg;
	if (err != NULL && errcap > 0) {
		const char *m =
		    "assembly not supported for architecture aarch64";
		size_t n = strlen(m);
		if (n >= errcap)
			n = errcap - 1;
		memcpy(err, m, n);
		err[n] = 0;
	}
	return -1;
}

static int
aarch64_assemble_patch(zaddr_t addr, size_t patch_len, const char *line,
    uint8_t *buf, size_t buflen, size_t *lenp,
    zarch_resolve_fn resolve, void *resolve_arg,
    char *err, size_t errcap)
{
	(void)addr;
	(void)patch_len;
	(void)line;
	(void)buf;
	(void)buflen;
	(void)lenp;
	(void)resolve;
	(void)resolve_arg;
	if (err != NULL && errcap > 0) {
		const char *m =
		    "patch assembly not supported for architecture aarch64";
		size_t n = strlen(m);
		if (n >= errcap)
			n = errcap - 1;
		memcpy(err, m, n);
		err[n] = 0;
	}
	return -1;
}

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
	.decode_one = aarch64_decode_one,
	.fallthrough = aarch64_fallthrough,
	.assemble_one = aarch64_assemble_one,
	.assemble_patch = aarch64_assemble_patch,
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
