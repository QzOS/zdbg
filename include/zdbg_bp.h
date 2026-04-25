/*
 * zdbg_bp.h - software breakpoint table.
 *
 * Software-breakpoint instruction bytes, length and post-trap PC
 * correction are owned by the architecture ops table referenced
 * from struct zbp_table::arch.  This module no longer hard-codes
 * x86-64 0xcc / RIP - 1 assumptions.
 *
 * To continue from a software breakpoint:
 *     restore the original bytes recorded in zbp::orig
 *     set the architecture's PC back to the breakpoint address
 *     single-step one instruction
 *     reinstall the architecture's breakpoint bytes
 *     continue
 */

#ifndef ZDBG_BP_H
#define ZDBG_BP_H

#include "zdbg.h"
#include "zdbg_arch.h"
#include "zdbg_target.h"
#include "zdbg_filter.h"
#include "zdbg_actions.h"

#define ZDBG_MAX_BREAKPOINTS 128

enum zbp_state {
	ZBP_EMPTY = 0,
	ZBP_ENABLED,
	ZBP_DISABLED
};

/*
 * A breakpoint carries two independent pieces of state:
 *
 *   - logical state (enum zbp_state): the user's intent, set by
 *     b/be/bd/bc commands.  A ZBP_ENABLED breakpoint should fire
 *     whenever the target reaches its address.
 *
 *   - installed flag: whether the architecture's breakpoint bytes
 *     are currently present in target memory at that address.
 *     When a breakpoint is hit, the debugger restores the original
 *     bytes, sets the PC back, and leaves the breakpoint logically
 *     enabled but uninstalled until the instruction has been
 *     stepped over.
 *
 * `orig` stores the original instruction bytes that were
 * overwritten by install.  `orig_len` records how many bytes were
 * saved (always equal to arch->breakpoint_len at install time).
 */

struct zbp {
	enum zbp_state state;
	zaddr_t addr;
	uint8_t orig[ZDBG_MAX_BREAKPOINT_BYTES];
	size_t  orig_len;
	int temporary;
	int installed;
	struct zstop_filter filter;
	struct zaction_list actions;
};

struct zbp_table {
	const struct zarch_ops *arch;
	struct zbp bp[ZDBG_MAX_BREAKPOINTS];
};

void zbp_table_init(struct zbp_table *bt, const struct zarch_ops *arch);
int  zbp_alloc(struct zbp_table *bt, zaddr_t addr, int temporary);
int  zbp_find_by_addr(struct zbp_table *bt, zaddr_t addr);
int  zbp_install(struct ztarget *t, struct zbp_table *bt, int id);
int  zbp_uninstall(struct ztarget *t, struct zbp_table *bt, int id);
int  zbp_enable(struct ztarget *t, struct zbp_table *bt, int id);
int  zbp_disable(struct ztarget *t, struct zbp_table *bt, int id);
int  zbp_clear(struct ztarget *t, struct zbp_table *bt, int id);
int  zbp_handle_trap(struct ztarget *t, struct zbp_table *bt,
    struct zregs *regs, int *idp);
int  zbp_reinstall_enabled(struct ztarget *t, struct zbp_table *bt);
void zbp_list(const struct zbp_table *bt);

#endif /* ZDBG_BP_H */
