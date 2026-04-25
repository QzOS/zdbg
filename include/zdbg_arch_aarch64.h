/*
 * zdbg_arch_aarch64.h - private declarations for the AArch64
 * disassembler/decoder.  These entry points are consumed by
 * arch_aarch64.c (the ops table wrapper) and by tests.  They
 * have no dependency on Linux ptrace headers and build on every
 * host.
 *
 * Phase-1 scope: a small fixed-width decoder that recognizes
 * common control-flow, prologue/epilogue, and a handful of
 * data-processing forms.  Unknown instructions are still
 * accepted and rendered as `.word 0xNNNNNNNN`.
 */

#ifndef ZDBG_ARCH_AARCH64_H
#define ZDBG_ARCH_AARCH64_H

#include "zdbg.h"
#include "zdbg_arch.h"

/*
 * Decode one AArch64 instruction at `addr` from `buf`.  At least
 * 4 bytes must be available; on success `out->len == 4`.  Unknown
 * encodings are reported as `.word 0xNNNNNNNN` with `kind ==
 * ZINSN_OTHER` and the function still returns 0.  Returns -1 only
 * on hard input errors (NULL out, buffer shorter than 4 bytes).
 */
int zaarch64_decode_one(zaddr_t addr, const uint8_t *buf,
    size_t buflen, struct zdecode *out);

/*
 * Address of the instruction following `d`.  AArch64 instructions
 * are always 4 bytes wide, so the result is `d->addr + 4` for any
 * successfully-decoded instruction.  Returns 0 on bad input.
 */
zaddr_t zaarch64_fallthrough(const struct zdecode *d);

#endif /* ZDBG_ARCH_AARCH64_H */
