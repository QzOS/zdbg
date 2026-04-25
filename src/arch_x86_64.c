/*
 * arch_x86_64.c - x86-64 target architecture ops table.
 *
 * Wraps the existing tinyasm/tinydis modules behind the generic
 * `struct zarch_ops` interface so the debugger core can stay
 * architecture-neutral.  No new x86-64 behavior is implemented
 * here; this module only routes generic ops through the legacy
 * APIs and converts data shapes between `struct ztinydis` and
 * `struct zdecode`.
 */

#include <stddef.h>
#include <string.h>

#include "zdbg_arch.h"
#include "zdbg_arch_x86_64.h"
#include "zdbg_maps.h"
#include "zdbg_regs.h"
#include "zdbg_target.h"
#include "zdbg_tinyasm.h"
#include "zdbg_tinydis.h"

static const uint8_t x86_64_brk[1] = { ZDBG_X86_INT3 };

/* enum ztinydis_kind value tags happen to match enum zinsn_kind for
 * every kind the legacy decoder produces except ZINSN_INT3, which
 * was renamed to ZINSN_BREAKPOINT in the generic enum.  Keep this
 * mapping localized so future architectures cannot leak the legacy
 * name. */
static enum zinsn_kind
map_kind(enum zinsn_kind k)
{
	/* ZINSN_INT3 has the same numeric value as ZINSN_BREAKPOINT
	 * by virtue of the enum reordering, so a direct cast is safe.
	 * The function exists to make the boundary explicit. */
	return k;
}

static int
x86_64_decode_one(zaddr_t addr, const uint8_t *buf, size_t buflen,
    struct zdecode *out)
{
	struct ztinydis dis;
	size_t copy_text;

	if (out == NULL)
		return -1;
	memset(out, 0, sizeof(*out));
	if (ztinydis_one(addr, buf, buflen, &dis) < 0)
		return -1;

	out->addr = dis.addr;
	if (dis.len > sizeof(out->bytes))
		out->len = sizeof(out->bytes);
	else
		out->len = dis.len;
	memcpy(out->bytes, dis.bytes, out->len);

	copy_text = sizeof(dis.text);
	if (copy_text >= sizeof(out->text))
		copy_text = sizeof(out->text) - 1;
	memcpy(out->text, dis.text, copy_text);
	out->text[copy_text] = 0;

	out->kind = map_kind(dis.kind);
	out->target = dis.target;
	out->has_target = dis.has_target;
	out->is_call = dis.is_call;
	out->is_branch = dis.is_branch;
	out->is_cond = dis.is_cond;
	return 0;
}

static zaddr_t
x86_64_fallthrough(const struct zdecode *d)
{
	if (d == NULL || d->len == 0)
		return 0;
	return d->addr + (zaddr_t)d->len;
}

static int
x86_64_assemble_one(zaddr_t addr, const char *line,
    uint8_t *buf, size_t buflen, size_t *lenp,
    zarch_resolve_fn resolve, void *resolve_arg,
    char *err, size_t errcap)
{
	struct ztinyasm enc;

	if (buf == NULL || lenp == NULL)
		return -1;
	if (ztinyasm_assemble_ex(addr, line, &enc,
	    (ztinyasm_resolve_fn)resolve, resolve_arg, err, errcap) < 0)
		return -1;
	if (enc.len > buflen) {
		if (err != NULL && errcap > 0) {
			const char *m = "instruction too long";
			size_t n = strlen(m);
			if (n >= errcap)
				n = errcap - 1;
			memcpy(err, m, n);
			err[n] = 0;
		}
		return -1;
	}
	memcpy(buf, enc.code, enc.len);
	*lenp = enc.len;
	return 0;
}

static int
x86_64_assemble_patch(zaddr_t addr, size_t patch_len, const char *line,
    uint8_t *buf, size_t buflen, size_t *lenp,
    zarch_resolve_fn resolve, void *resolve_arg,
    char *err, size_t errcap)
{
	/* zarch_resolve_fn and ztinyasm_resolve_fn share the same
	 * signature by design. */
	return ztinyasm_patch_ex(addr, patch_len, line, buf, buflen,
	    lenp, (ztinyasm_resolve_fn)resolve, resolve_arg, err, errcap);
}

static int
x86_64_invert_jcc(uint8_t *buf, size_t len, size_t *usedp)
{
	return zpatch_invert_jcc(buf, len, usedp);
}

static int
x86_64_get_pc(const struct zregs *regs, zaddr_t *pcp)
{
	if (regs == NULL || pcp == NULL)
		return -1;
	*pcp = (zaddr_t)regs->rip;
	return 0;
}

static int
x86_64_set_pc(struct zregs *regs, zaddr_t pc)
{
	if (regs == NULL)
		return -1;
	regs->rip = (uint64_t)pc;
	return 0;
}

static int
x86_64_get_sp(const struct zregs *regs, zaddr_t *spp)
{
	if (regs == NULL || spp == NULL)
		return -1;
	*spp = (zaddr_t)regs->rsp;
	return 0;
}

static int
x86_64_get_fp(const struct zregs *regs, zaddr_t *fpp)
{
	if (regs == NULL || fpp == NULL)
		return -1;
	*fpp = (zaddr_t)regs->rbp;
	return 0;
}

static zaddr_t
x86_64_breakpoint_pc_after_trap(zaddr_t pc)
{
	/* int3 (0xcc) trap: kernel reports RIP just past the int3
	 * byte.  The breakpoint address is one byte before. */
	if (pc == 0)
		return 0;
	return pc - 1;
}

/*
 * x86-64 user-space canonical user-half check.  Identical to the
 * conservative check the command layer used to do inline.
 */
static int
x86_64_canon_user(uint64_t a)
{
	if (a < 0x1000)
		return 0;
	if (a >= 0x0000800000000000ULL)
		return 0;
	return 1;
}

static int
x86_64_read_u64_le(struct ztarget *tgt, zaddr_t addr, uint64_t *out)
{
	uint8_t b[8];
	uint64_t v;
	int i;

	if (ztarget_read(tgt, addr, b, sizeof(b)) < 0)
		return -1;
	v = 0;
	for (i = 0; i < 8; i++)
		v |= (uint64_t)b[i] << (i * 8);
	*out = v;
	return 0;
}

static int
x86_64_backtrace_fp(struct ztarget *target, const struct zregs *regs,
    const struct zmap_table *maps, int max_frames,
    void (*emit)(void *arg, int idx, zaddr_t addr), void *arg)
{
	const uint64_t frame_delta_max = 0x100000ULL; /* 1 MiB */
	uint64_t rip;
	uint64_t rbp;
	int i;

	if (target == NULL || regs == NULL || emit == NULL ||
	    max_frames <= 0)
		return -1;
	rip = regs->rip;
	rbp = regs->rbp;
	emit(arg, 0, (zaddr_t)rip);

	for (i = 1; i < max_frames; i++) {
		uint64_t next_rbp = 0;
		uint64_t retaddr = 0;

		if (!x86_64_canon_user(rbp))
			break;
		if (x86_64_read_u64_le(target, (zaddr_t)rbp,
		    &next_rbp) < 0)
			break;
		if (x86_64_read_u64_le(target, (zaddr_t)(rbp + 8),
		    &retaddr) < 0)
			break;
		if (retaddr == 0)
			break;
		if (!x86_64_canon_user(retaddr))
			break;
		/* frame pointer must advance upward on x86-64 SysV */
		if (next_rbp <= rbp)
			break;
		if (next_rbp - rbp > frame_delta_max)
			break;
		if (maps != NULL) {
			const struct zmap *mr;
			const struct zmap *mb;
			mr = zmaps_find_by_addr(maps, (zaddr_t)retaddr);
			mb = zmaps_find_by_addr(maps, (zaddr_t)next_rbp);
			if (mr == NULL || mb == NULL)
				break;
			if (strchr(mr->perms, 'x') == NULL)
				break;
		}
		emit(arg, i, (zaddr_t)retaddr);
		rbp = next_rbp;
		rip = retaddr;
	}
	return 0;
}

static const struct zarch_ops x86_64_ops = {
	.arch = ZARCH_X86_64,
	.name = "x86-64",
	.breakpoint_bytes = x86_64_brk,
	.breakpoint_len = sizeof(x86_64_brk),
	.decode_one = x86_64_decode_one,
	.fallthrough = x86_64_fallthrough,
	.assemble_one = x86_64_assemble_one,
	.assemble_patch = x86_64_assemble_patch,
	.invert_jcc = x86_64_invert_jcc,
	.get_pc = x86_64_get_pc,
	.set_pc = x86_64_set_pc,
	.get_sp = x86_64_get_sp,
	.get_fp = x86_64_get_fp,
	.pc_reg_name = "rip",
	.sp_reg_name = "rsp",
	.fp_reg_name = "rbp",
	.breakpoint_pc_after_trap = x86_64_breakpoint_pc_after_trap,
	.regs_print = zregs_print,
	.regs_get_by_name = zregs_get_by_name,
	.regs_set_by_name = zregs_set_by_name,
	.backtrace_fp = x86_64_backtrace_fp
};

const struct zarch_ops *
zarch_x86_64(void)
{
	return &x86_64_ops;
}
