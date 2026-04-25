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
		const char *m = "AArch64 patch assembly not supported";
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

static const struct zarch_ops aarch64_ops = {
	ZARCH_AARCH64,
	"aarch64",
	aarch64_brk,
	sizeof(aarch64_brk),
	aarch64_decode_one,
	aarch64_fallthrough,
	aarch64_assemble_patch,
	aarch64_invert_jcc,
	aarch64_unsupported_get,
	aarch64_unsupported_set,
	aarch64_unsupported_get,
	aarch64_unsupported_get,
	"pc",
	"sp",
	"x29",
	aarch64_breakpoint_pc_after_trap
};

const struct zarch_ops *
zarch_aarch64(void)
{
	return &aarch64_ops;
}
