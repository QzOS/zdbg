/*
 * bp.c - breakpoint table bookkeeping.
 *
 * Keeps a small fixed-size table of software breakpoints.  The
 * table separates a breakpoint's logical state (enabled, disabled
 * or empty) from its installed state (are the architecture's
 * breakpoint bytes currently present in target memory).  This
 * separation is what lets the command layer temporarily remove the
 * breakpoint while executing the original instruction after a hit,
 * then reinstall it.
 *
 * Architecture-specific concerns (breakpoint bytes, breakpoint
 * length, post-trap PC adjustment, generic PC access) are routed
 * through the zarch_ops table that the table was initialized with.
 * No x86-specific bytes appear here.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_arch.h"
#include "zdbg_bp.h"

static int
valid_id(int id)
{
	return id >= 0 && id < ZDBG_MAX_BREAKPOINTS;
}

static int
target_live(struct ztarget *t)
{
	return t != NULL && t->state != ZTARGET_EMPTY &&
	    t->state != ZTARGET_EXITED && t->state != ZTARGET_DETACHED;
}

void
zbp_table_init(struct zbp_table *bt, const struct zarch_ops *arch)
{
	if (bt == NULL)
		return;
	memset(bt, 0, sizeof(*bt));
	bt->arch = arch;
}

int
zbp_alloc(struct zbp_table *bt, zaddr_t addr, int temporary)
{
	int i;

	if (bt == NULL)
		return -1;

	/* reuse an existing entry for the same address */
	for (i = 0; i < ZDBG_MAX_BREAKPOINTS; i++) {
		if (bt->bp[i].state != ZBP_EMPTY && bt->bp[i].addr == addr)
			return i;
	}

	for (i = 0; i < ZDBG_MAX_BREAKPOINTS; i++) {
		if (bt->bp[i].state == ZBP_EMPTY) {
			bt->bp[i].state = ZBP_DISABLED;
			bt->bp[i].addr = addr;
			memset(bt->bp[i].orig, 0, sizeof(bt->bp[i].orig));
			bt->bp[i].orig_len = 0;
			bt->bp[i].temporary = temporary ? 1 : 0;
			bt->bp[i].installed = 0;
			zfilter_init(&bt->bp[i].filter);
			zactions_init(&bt->bp[i].actions);
			return i;
		}
	}
	return -1;
}

int
zbp_find_by_addr(struct zbp_table *bt, zaddr_t addr)
{
	int i;

	if (bt == NULL)
		return -1;
	for (i = 0; i < ZDBG_MAX_BREAKPOINTS; i++) {
		if (bt->bp[i].state != ZBP_EMPTY && bt->bp[i].addr == addr)
			return i;
	}
	return -1;
}

int
zbp_install(struct ztarget *t, struct zbp_table *bt, int id)
{
	struct zbp *b;
	uint8_t orig[ZDBG_MAX_BREAKPOINT_BYTES];
	const struct zarch_ops *arch;
	size_t bplen;

	if (bt == NULL || !valid_id(id))
		return -1;
	arch = bt->arch;
	if (arch == NULL || arch->breakpoint_bytes == NULL ||
	    arch->breakpoint_len == 0 ||
	    arch->breakpoint_len > sizeof(orig))
		return -1;
	bplen = arch->breakpoint_len;

	b = &bt->bp[id];
	if (b->state != ZBP_ENABLED)
		return -1;
	if (b->installed)
		return 0;
	if (!target_live(t))
		return -1;
	if (ztarget_read(t, b->addr, orig, bplen) < 0)
		return -1;
	if (ztarget_write(t, b->addr, arch->breakpoint_bytes, bplen) < 0)
		return -1;
	(void)ztarget_flush_icache(t, b->addr, bplen);
	memcpy(b->orig, orig, bplen);
	b->orig_len = bplen;
	b->installed = 1;
	return 0;
}

int
zbp_uninstall(struct ztarget *t, struct zbp_table *bt, int id)
{
	struct zbp *b;

	if (bt == NULL || !valid_id(id))
		return -1;
	b = &bt->bp[id];
	if (b->state == ZBP_EMPTY)
		return -1;
	if (!b->installed)
		return 0;
	if (!target_live(t))
		return -1;
	if (b->orig_len == 0 || b->orig_len > sizeof(b->orig))
		return -1;
	if (ztarget_write(t, b->addr, b->orig, b->orig_len) < 0)
		return -1;
	(void)ztarget_flush_icache(t, b->addr, b->orig_len);
	b->installed = 0;
	return 0;
}

int
zbp_enable(struct ztarget *t, struct zbp_table *bt, int id)
{
	struct zbp *b;

	if (bt == NULL || !valid_id(id))
		return -1;
	b = &bt->bp[id];
	if (b->state == ZBP_EMPTY)
		return -1;
	if (b->state == ZBP_ENABLED && b->installed)
		return 0;
	b->state = ZBP_ENABLED;
	if (target_live(t) && t->state == ZTARGET_STOPPED && !b->installed)
		return zbp_install(t, bt, id);
	return 0;
}

int
zbp_disable(struct ztarget *t, struct zbp_table *bt, int id)
{
	struct zbp *b;

	if (bt == NULL || !valid_id(id))
		return -1;
	b = &bt->bp[id];
	if (b->state == ZBP_EMPTY)
		return -1;
	if (b->installed) {
		if (zbp_uninstall(t, bt, id) < 0)
			return -1;
	}
	b->state = ZBP_DISABLED;
	return 0;
}

int
zbp_clear(struct ztarget *t, struct zbp_table *bt, int id)
{
	struct zbp *b;

	if (bt == NULL || !valid_id(id))
		return -1;
	b = &bt->bp[id];
	if (b->state == ZBP_EMPTY)
		return 0;
	if (b->installed)
		(void)zbp_uninstall(t, bt, id);
	memset(b, 0, sizeof(*b));
	return 0;
}

int
zbp_handle_trap(struct ztarget *t, struct zbp_table *bt,
    struct zregs *regs, int *idp)
{
	const struct zarch_ops *arch;
	zaddr_t pc;
	zaddr_t trap_addr;
	int id;
	struct zbp *b;

	if (idp != NULL)
		*idp = -1;
	if (bt == NULL || regs == NULL)
		return -1;
	arch = bt->arch;
	if (arch == NULL || arch->get_pc == NULL || arch->set_pc == NULL ||
	    arch->breakpoint_pc_after_trap == NULL)
		return -1;

	if (arch->get_pc(regs, &pc) < 0)
		return -1;
	/* Avoid underflow for architectures whose PC adjustment
	 * subtracts (e.g. x86 -1 on a bogus PC of 0). */
	if (pc == 0)
		return 0;
	trap_addr = arch->breakpoint_pc_after_trap(pc);

	id = zbp_find_by_addr(bt, trap_addr);
	if (id < 0)
		return 0;
	b = &bt->bp[id];
	/* Only recognize as ours if this breakpoint was actually
	 * armed in target memory.  A logically enabled but not yet
	 * installed entry must not claim arbitrary traps. */
	if (b->state != ZBP_ENABLED || !b->installed)
		return 0;

	if (zbp_uninstall(t, bt, id) < 0)
		return -1;
	if (arch->set_pc(regs, trap_addr) < 0)
		return -1;
	if (!target_live(t) || ztarget_setregs(t, regs) < 0)
		return -1;
	if (idp != NULL)
		*idp = id;
	return 1;
}

int
zbp_reinstall_enabled(struct ztarget *t, struct zbp_table *bt)
{
	int i;
	int rc = 0;

	if (bt == NULL)
		return -1;
	for (i = 0; i < ZDBG_MAX_BREAKPOINTS; i++) {
		struct zbp *b = &bt->bp[i];
		if (b->state != ZBP_ENABLED || b->installed)
			continue;
		if (zbp_install(t, bt, i) < 0)
			rc = -1;
	}
	return rc;
}

void
zbp_list(const struct zbp_table *bt)
{
	int i;
	int any = 0;

	if (bt == NULL)
		return;
	for (i = 0; i < ZDBG_MAX_BREAKPOINTS; i++) {
		const struct zbp *b = &bt->bp[i];
		const char *s;
		const char *ins;
		char cond[ZDBG_FILTER_EXPR_MAX + 8];
		char act[32];
		if (b->state == ZBP_EMPTY)
			continue;
		s = (b->state == ZBP_ENABLED) ? "enabled " : "disabled";
		ins = b->installed ? "installed" : "removed  ";
		if (b->filter.has_cond)
			snprintf(cond, sizeof(cond), "cond=\"%s\"",
			    b->filter.cond);
		else
			snprintf(cond, sizeof(cond), "cond=none");
		if (b->actions.silent)
			snprintf(act, sizeof(act), "actions=%d silent",
			    b->actions.count);
		else
			snprintf(act, sizeof(act), "actions=%d",
			    b->actions.count);
		printf(" %3d %s %s hits=%llu ignore=%llu %s %s %016llx%s\n",
		    i, s, ins,
		    (unsigned long long)b->filter.hits,
		    (unsigned long long)b->filter.ignore,
		    cond, act,
		    (unsigned long long)b->addr,
		    b->temporary ? " (tmp)" : "");
		any = 1;
	}
	if (!any)
		printf(" no breakpoints\n");
}
