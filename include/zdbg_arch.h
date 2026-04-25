/*
 * zdbg_arch.h - generic target-architecture abstraction.
 *
 * The debugger separates two axes:
 *
 *   OS backend           Linux ptrace, Windows Debug API
 *   Target architecture  x86-64, AArch64 (stub for now)
 *
 * The OS backend owns process control, wait/stop handling, memory
 * access, thread enumeration, and OS signal/exception mechanics.
 *
 * The target architecture (this header) owns instruction decoding,
 * tiny patch assembly, software-breakpoint instruction bytes and
 * length, software-breakpoint PC correction after a trap, and
 * abstract PC/SP/FP register access.  Generic command/breakpoint
 * code must reach for x86-specific bytes or for `regs.rip` only
 * through the ops table declared here.
 */

#ifndef ZDBG_ARCH_H
#define ZDBG_ARCH_H

#include "zdbg.h"

struct zregs;

enum zarch {
	ZARCH_NONE = 0,
	ZARCH_X86_64,
	ZARCH_AARCH64
};

/*
 * Generic instruction kind.  Architecture decoders should map their
 * own opcode taxonomy onto these.  Unknown encodings stay as
 * ZINSN_OTHER and are still printable as their architecture's
 * `db`-style fallback.
 */
enum zinsn_kind {
	ZINSN_OTHER = 0,
	ZINSN_NOP,
	ZINSN_BREAKPOINT,
	ZINSN_RET,
	ZINSN_CALL,
	ZINSN_JMP,
	ZINSN_JCC,
	ZINSN_PUSH,
	ZINSN_POP,
	ZINSN_MOV,
	ZINSN_LEA,
	ZINSN_ADD,
	ZINSN_SUB,
	ZINSN_CMP,
	ZINSN_TEST,
	ZINSN_XOR
};

/* Maximum bytes a software breakpoint may occupy in target memory.
 * x86-64 needs 1 (0xcc).  AArch64 needs 4 (BRK #0).  The breakpoint
 * table stores up to this many original bytes per slot. */
#define ZDBG_MAX_BREAKPOINT_BYTES 8

/* Maximum bytes a single decoded instruction may occupy.  Both
 * x86-64 (15) and AArch64 (4) fit comfortably. */
#define ZDBG_MAX_INSN_BYTES 16

struct zdecode {
	zaddr_t addr;
	uint8_t bytes[ZDBG_MAX_INSN_BYTES];
	size_t  len;
	char    text[96];

	enum zinsn_kind kind;
	zaddr_t target;
	int     has_target;
	int     is_call;
	int     is_branch;
	int     is_cond;
};

/*
 * Operand resolver for assemble_patch.  Identical contract to
 * ztinyasm_resolve_fn: resolve `expr` to an absolute address,
 * return 0 on success, -1 on error.
 */
typedef int (*zarch_resolve_fn)(void *arg, const char *expr,
    zaddr_t *out);

/*
 * Architecture operations table.  Function pointers may be NULL
 * to indicate "this architecture does not support that operation".
 * Generic code must check for NULL or treat -1 as "unsupported".
 */
struct zarch_ops {
	enum zarch  arch;
	const char *name;

	/* Software-breakpoint instruction bytes (length-prefixed). */
	const uint8_t *breakpoint_bytes;
	size_t         breakpoint_len;

	/*
	 * Decode one instruction at `addr` from `buf` (`buflen`
	 * bytes available).  Fills `out` and returns 0 on success,
	 * -1 on a hard error.  When the architecture cannot recognise
	 * the encoding it should still return 0 with a `db`-style
	 * fallback in `out->text` and `out->len` advanced by 1.
	 */
	int (*decode_one)(zaddr_t addr, const uint8_t *buf,
	    size_t buflen, struct zdecode *out);

	/* Address of the instruction following `d`.  Returns 0 on
	 * a bad decode (d == NULL or d->len == 0). */
	zaddr_t (*fallthrough)(const struct zdecode *d);

	/*
	 * Encode a single source line into a fixed-size patch slot
	 * starting at `addr`.  Behaves like ztinyasm_patch_ex():
	 * pads any unused tail with the architecture's NOP, fails
	 * if encoding overflows `patch_len`.  Returns 0 on success
	 * with `*lenp` set to `patch_len`, -1 on error.
	 */
	int (*assemble_patch)(zaddr_t addr, size_t patch_len,
	    const char *line, uint8_t *buf, size_t buflen,
	    size_t *lenp, zarch_resolve_fn resolve, void *resolve_arg,
	    char *err, size_t errcap);

	/*
	 * Invert a single conditional jump in `buf`.  On success
	 * `*usedp` receives the instruction length.  Returns 0 on
	 * success, -1 if the architecture does not support the
	 * operation or no recognized conditional is at buf.
	 */
	int (*invert_jcc)(uint8_t *buf, size_t len, size_t *usedp);

	/* Generic register accessors.  All return 0 on success and
	 * -1 if the architecture cannot honor the request. */
	int (*get_pc)(const struct zregs *regs, zaddr_t *pcp);
	int (*set_pc)(struct zregs *regs, zaddr_t pc);
	int (*get_sp)(const struct zregs *regs, zaddr_t *spp);
	int (*get_fp)(const struct zregs *regs, zaddr_t *fpp);

	/* Names of the canonical PC/SP/FP registers (printed in
	 * diagnostics).  May be NULL if not applicable. */
	const char *pc_reg_name;
	const char *sp_reg_name;
	const char *fp_reg_name;

	/*
	 * Adjust the PC reported by the OS backend after a software
	 * breakpoint trap to point at the breakpoint instruction
	 * itself.  On x86-64 this is `pc - 1`.  On AArch64 the OS
	 * already reports BRK at the BRK PC, so this is `pc`.
	 */
	zaddr_t (*breakpoint_pc_after_trap)(zaddr_t pc);
};

/* Returns the ops table for `arch`, or NULL for ZARCH_NONE / an
 * unsupported architecture id. */
const struct zarch_ops *zarch_get(enum zarch arch);

/* Convenience accessors for the two known architectures. */
const struct zarch_ops *zarch_x86_64(void);
const struct zarch_ops *zarch_aarch64(void);

#endif /* ZDBG_ARCH_H */
