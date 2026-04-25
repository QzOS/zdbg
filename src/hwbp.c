/*
 * hwbp.c - x86-64 hardware breakpoint/watchpoint bookkeeping.
 *
 * The table mirrors the four DR0..DR3 debug register slots.
 * Table id == DR slot index, which makes DR6 bit decoding on
 * trap trivial.  We only ever use local enable bits (L0..L3)
 * in DR7 and the per-slot RW/LEN fields.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_hwbp.h"
#include "zdbg_symbols.h"
#include "zdbg_target.h"

/* DR7 per-slot bit layout (slot n in [0..3]):
 *   Ln (local enable) at bit 2*n         (bits 0, 2, 4, 6)
 *   RW field          at bits 16 + 4*n   (2 bits)
 *   LEN field         at bits 18 + 4*n   (2 bits)
 * RW encoding:  00 exec, 01 write, 11 read/write
 * LEN encoding: 00 1B, 01 2B, 11 4B, 10 8B (x86-64)
 */

static int
valid_id(int id)
{
	return id >= 0 && id < ZDBG_MAX_HWBP;
}

static int
target_live(struct ztarget *t)
{
	return t != NULL && t->state != ZTARGET_EMPTY &&
	    t->state != ZTARGET_EXITED && t->state != ZTARGET_DETACHED;
}

static int
len_to_dr7_field(int len)
{
	switch (len) {
	case 1: return 0x0;
	case 2: return 0x1;
	case 4: return 0x3;
	case 8: return 0x2;
	default: return -1;
	}
}

static int
kind_to_dr7_field(enum zhwbp_kind kind)
{
	switch (kind) {
	case ZHWBP_EXEC:      return 0x0;
	case ZHWBP_WRITE:     return 0x1;
	case ZHWBP_READWRITE: return 0x3;
	}
	return -1;
}

void
zhwbp_table_init(struct zhwbp_table *ht)
{
	if (ht == NULL)
		return;
	memset(ht, 0, sizeof(*ht));
}

int
zhwbp_validate(enum zhwbp_kind kind, int len, zaddr_t addr)
{
	if (kind == ZHWBP_EXEC) {
		if (len != 1)
			return -1;
		return 0;
	}
	if (kind != ZHWBP_WRITE && kind != ZHWBP_READWRITE)
		return -1;
	if (len != 1 && len != 2 && len != 4 && len != 8)
		return -1;
	if ((addr % (zaddr_t)len) != 0)
		return -1;
	return 0;
}

int
zhwbp_alloc(struct zhwbp_table *ht, zaddr_t addr,
    enum zhwbp_kind kind, int len)
{
	int i;

	if (ht == NULL)
		return -1;
	if (zhwbp_validate(kind, len, addr) < 0)
		return -1;
	for (i = 0; i < ZDBG_MAX_HWBP; i++) {
		if (ht->bp[i].state == ZHWBP_EMPTY) {
			ht->bp[i].state = ZHWBP_DISABLED;
			ht->bp[i].kind = kind;
			ht->bp[i].addr = addr;
			ht->bp[i].len = len;
			zfilter_init(&ht->bp[i].filter);
			return i;
		}
	}
	return -1;
}

uint64_t
zhwbp_build_dr7(const struct zhwbp_table *ht)
{
	uint64_t dr7 = 0;
	int i;

	if (ht == NULL)
		return 0;
	for (i = 0; i < ZDBG_MAX_HWBP; i++) {
		const struct zhwbp *b = &ht->bp[i];
		int rw;
		int lf;

		if (b->state != ZHWBP_ENABLED)
			continue;
		rw = kind_to_dr7_field(b->kind);
		lf = len_to_dr7_field(b->len);
		if (rw < 0 || lf < 0)
			continue;
		/* local enable bit for slot i */
		dr7 |= (uint64_t)1 << (2 * i);
		/* RW field */
		dr7 |= (uint64_t)(rw & 0x3) << (16 + 4 * i);
		/* LEN field */
		dr7 |= (uint64_t)(lf & 0x3) << (18 + 4 * i);
	}
	return dr7;
}

int
zhwbp_program(struct ztarget *t, const struct zhwbp_table *ht)
{
	uint64_t dr7;
	int i;

	if (ht == NULL || !target_live(t))
		return -1;
	/* Program DR7 = 0 first so no stale slot fires mid-update. */
	if (ztarget_set_debugreg_all(t, 7, 0) < 0)
		return -1;
	for (i = 0; i < ZDBG_MAX_HWBP; i++) {
		uint64_t a = 0;
		if (ht->bp[i].state == ZHWBP_ENABLED)
			a = (uint64_t)ht->bp[i].addr;
		if (ztarget_set_debugreg_all(t, i, a) < 0)
			return -1;
	}
	dr7 = zhwbp_build_dr7(ht);
	if (ztarget_set_debugreg_all(t, 7, dr7) < 0)
		return -1;
	return 0;
}

int
zhwbp_enable(struct ztarget *t, struct zhwbp_table *ht, int id)
{
	struct zhwbp *b;

	if (ht == NULL || !valid_id(id))
		return -1;
	b = &ht->bp[id];
	if (b->state == ZHWBP_EMPTY)
		return -1;
	if (zhwbp_validate(b->kind, b->len, b->addr) < 0)
		return -1;
	b->state = ZHWBP_ENABLED;
	if (target_live(t) && t->state == ZTARGET_STOPPED)
		return zhwbp_program(t, ht);
	return 0;
}

int
zhwbp_disable(struct ztarget *t, struct zhwbp_table *ht, int id)
{
	struct zhwbp *b;

	if (ht == NULL || !valid_id(id))
		return -1;
	b = &ht->bp[id];
	if (b->state == ZHWBP_EMPTY)
		return -1;
	b->state = ZHWBP_DISABLED;
	if (target_live(t) && t->state == ZTARGET_STOPPED)
		return zhwbp_program(t, ht);
	return 0;
}

int
zhwbp_clear(struct ztarget *t, struct zhwbp_table *ht, int id)
{
	struct zhwbp *b;

	if (ht == NULL || !valid_id(id))
		return -1;
	b = &ht->bp[id];
	if (b->state == ZHWBP_EMPTY)
		return 0;
	memset(b, 0, sizeof(*b));
	if (target_live(t) && t->state == ZTARGET_STOPPED)
		(void)zhwbp_program(t, ht);
	return 0;
}

int
zhwbp_clear_all(struct ztarget *t, struct zhwbp_table *ht)
{
	int i;

	if (ht == NULL)
		return -1;
	for (i = 0; i < ZDBG_MAX_HWBP; i++)
		memset(&ht->bp[i], 0, sizeof(ht->bp[i]));
	if (target_live(t) && t->state == ZTARGET_STOPPED) {
		/* best-effort: clear DR7 + DR0..DR3 + DR6 in every thread */
		(void)ztarget_set_debugreg_all(t, 7, 0);
		for (i = 0; i < ZDBG_MAX_HWBP; i++)
			(void)ztarget_set_debugreg_all(t, i, 0);
		(void)ztarget_set_debugreg_all(t, 6, 0);
	}
	return 0;
}

int
zhwbp_handle_trap(struct ztarget *t, struct zhwbp_table *ht,
    int *idp, uint64_t *dr6p)
{
	uint64_t dr6 = 0;
	int i;
	int hit = -1;

	if (idp != NULL)
		*idp = -1;
	if (dr6p != NULL)
		*dr6p = 0;
	if (ht == NULL || !target_live(t))
		return -1;

	if (ztarget_get_debugreg(t, 6, &dr6) < 0)
		return -1;
	if (dr6p != NULL)
		*dr6p = dr6;
	for (i = 0; i < ZDBG_MAX_HWBP; i++) {
		if ((dr6 & ((uint64_t)1 << i)) == 0)
			continue;
		if (ht->bp[i].state == ZHWBP_ENABLED) {
			hit = i;
			break;
		}
	}
	if (hit < 0)
		return 0;

	/*
	 * Clear DR6 wholesale so stale B0..B3 bits do not cause
	 * future false reports.  BS/BT/BD/RTM are also cleared;
	 * zdbg does not currently track those causes.
	 */
	(void)ztarget_set_debugreg(t, 6, 0);

	if (idp != NULL)
		*idp = hit;
	return 1;
}

static const char *
kind_name(enum zhwbp_kind k)
{
	switch (k) {
	case ZHWBP_EXEC:      return "exec     ";
	case ZHWBP_WRITE:     return "write    ";
	case ZHWBP_READWRITE: return "readwrite";
	}
	return "?";
}

void
zhwbp_list(const struct zhwbp_table *ht)
{
	int i;
	int any = 0;

	if (ht == NULL)
		return;
	for (i = 0; i < ZDBG_MAX_HWBP; i++) {
		const struct zhwbp *b = &ht->bp[i];
		const char *s;

		if (b->state == ZHWBP_EMPTY)
			continue;
		s = (b->state == ZHWBP_ENABLED) ? "enabled " : "disabled";
		printf(" %d %s %s len=%d %016llx\n", i, s,
		    kind_name(b->kind), b->len,
		    (unsigned long long)b->addr);
		any = 1;
	}
	if (!any)
		printf(" no hardware breakpoints\n");
}
