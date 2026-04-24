/*
 * bp.c - breakpoint table bookkeeping.
 *
 * Keeps a small fixed-size table of breakpoints.  Actual
 * installation/removal depends on the target backend being able
 * to read and write memory.  Under the null backend, enable and
 * disable report a clean failure.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_arch.h"
#include "zdbg_bp.h"

void
zbp_table_init(struct zbp_table *bt)
{
	if (bt == NULL)
		return;
	memset(bt, 0, sizeof(*bt));
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
			bt->bp[i].orig = 0;
			bt->bp[i].temporary = temporary ? 1 : 0;
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
zbp_enable(struct ztarget *t, struct zbp_table *bt, int id)
{
	struct zbp *b;
	uint8_t orig;
	uint8_t cc;

	if (bt == NULL || id < 0 || id >= ZDBG_MAX_BREAKPOINTS)
		return -1;
	b = &bt->bp[id];
	if (b->state == ZBP_EMPTY)
		return -1;
	if (b->state == ZBP_ENABLED)
		return 0;

	if (t == NULL || t->state == ZTARGET_EMPTY)
		return -1;
	if (ztarget_read(t, b->addr, &orig, 1) < 0)
		return -1;
	cc = ZDBG_X86_INT3;
	if (ztarget_write(t, b->addr, &cc, 1) < 0)
		return -1;
	b->orig = orig;
	b->state = ZBP_ENABLED;
	return 0;
}

int
zbp_disable(struct ztarget *t, struct zbp_table *bt, int id)
{
	struct zbp *b;

	if (bt == NULL || id < 0 || id >= ZDBG_MAX_BREAKPOINTS)
		return -1;
	b = &bt->bp[id];
	if (b->state == ZBP_EMPTY)
		return -1;
	if (b->state == ZBP_DISABLED)
		return 0;

	if (t == NULL || t->state == ZTARGET_EMPTY)
		return -1;
	if (ztarget_write(t, b->addr, &b->orig, 1) < 0)
		return -1;
	b->state = ZBP_DISABLED;
	return 0;
}

int
zbp_clear(struct ztarget *t, struct zbp_table *bt, int id)
{
	struct zbp *b;

	if (bt == NULL || id < 0 || id >= ZDBG_MAX_BREAKPOINTS)
		return -1;
	b = &bt->bp[id];
	if (b->state == ZBP_EMPTY)
		return 0;

	if (b->state == ZBP_ENABLED) {
		/* best-effort restore */
		if (t != NULL && t->state != ZTARGET_EMPTY)
			(void)ztarget_write(t, b->addr, &b->orig, 1);
	}
	memset(b, 0, sizeof(*b));
	return 0;
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
		if (b->state == ZBP_EMPTY)
			continue;
		s = (b->state == ZBP_ENABLED) ? "enabled" : "disabled";
		printf(" %3d %-8s %016llx%s\n", i, s,
		    (unsigned long long)b->addr,
		    b->temporary ? " (tmp)" : "");
		any = 1;
	}
	if (!any)
		printf(" no breakpoints\n");
}
