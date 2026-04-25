/*
 * zdbg_hwbp.h - x86-64 hardware breakpoint/watchpoint table.
 *
 * Models the four x86 debug-register slots DR0..DR3 plus DR6/DR7.
 * Table index maps directly to the DRn slot, which keeps DR6
 * handling trivial: bit n in DR6 tells us which slot fired.
 *
 * Only local enable bits are used.  Supported types are:
 *   ZHWBP_EXEC       execute (length must be 1)
 *   ZHWBP_WRITE      data write
 *   ZHWBP_READWRITE  data read/write
 *
 * Data watchpoints require natural alignment (addr % len == 0)
 * and length in {1, 2, 4, 8}.  x86 has no read-only data
 * watchpoint encoding so there is no ZHWBP_READ.
 *
 * Hardware breakpoints/watchpoints apply only to the currently
 * traced Linux task.  Multi-thread propagation is out of scope.
 */

#ifndef ZDBG_HWBP_H
#define ZDBG_HWBP_H

#include "zdbg.h"
#include "zdbg_target.h"
#include "zdbg_filter.h"

#define ZDBG_MAX_HWBP 4

enum zhwbp_state {
	ZHWBP_EMPTY = 0,
	ZHWBP_ENABLED,
	ZHWBP_DISABLED
};

enum zhwbp_kind {
	ZHWBP_EXEC = 0,
	ZHWBP_WRITE,
	ZHWBP_READWRITE
};

struct zhwbp {
	enum zhwbp_state state;
	enum zhwbp_kind kind;
	zaddr_t addr;
	int len;
	struct zstop_filter filter;
};

struct zhwbp_table {
	struct zhwbp bp[ZDBG_MAX_HWBP];
};

void zhwbp_table_init(struct zhwbp_table *ht);

/*
 * Validate (kind, len, addr) combination.  Returns 0 if the
 * tuple is legal to program into a debug-register slot.
 */
int zhwbp_validate(enum zhwbp_kind kind, int len, zaddr_t addr);

/*
 * Allocate the first empty slot for the given address/kind/len.
 * On success returns the slot id in [0, ZDBG_MAX_HWBP) and the
 * slot is left in ZHWBP_DISABLED state.  The caller must invoke
 * zhwbp_enable() to program the debug registers.
 *
 * Returns -1 on invalid arguments or when all slots are used.
 */
int zhwbp_alloc(struct zhwbp_table *ht, zaddr_t addr,
    enum zhwbp_kind kind, int len);

int zhwbp_enable(struct ztarget *t, struct zhwbp_table *ht, int id);
int zhwbp_disable(struct ztarget *t, struct zhwbp_table *ht, int id);
int zhwbp_clear(struct ztarget *t, struct zhwbp_table *ht, int id);
int zhwbp_clear_all(struct ztarget *t, struct zhwbp_table *ht);

/*
 * Rewrite DR0..DR3 and DR7 in the target from the current table
 * contents.  Used internally by enable/disable/clear, exposed so
 * the command layer can force a reprogram (e.g. after attach).
 */
int zhwbp_program(struct ztarget *t, const struct zhwbp_table *ht);

/*
 * Inspect DR6 after a SIGTRAP and decide whether a table slot
 * fired.  On hit, returns 1 with *idp set to the slot id and
 * *dr6p (if non-NULL) set to the DR6 value that was read; DR6
 * is cleared in the target afterwards.  Returns 0 when no known
 * slot matches, -1 on error.
 */
int zhwbp_handle_trap(struct ztarget *t, struct zhwbp_table *ht,
    int *idp, uint64_t *dr6p);

void zhwbp_list(const struct zhwbp_table *ht);

/*
 * Build the DR7 value that corresponds to ht.  Exposed for
 * unit tests.  Only local-enable bits and RW/LEN fields are
 * set; reserved bits are left zero.
 */
uint64_t zhwbp_build_dr7(const struct zhwbp_table *ht);

#endif /* ZDBG_HWBP_H */
