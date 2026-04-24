/*
 * zdbg_bp.h - software breakpoint table.
 *
 * On x86-64 int3 trap, RIP points after the CC byte.
 * A real breakpoint handler must check RIP - 1.
 * To continue from a software breakpoint:
 *     restore original byte
 *     set RIP back to breakpoint address
 *     single-step one instruction
 *     reinsert CC
 *     continue
 *
 * This full sequence is deliberately not implemented in the
 * initial framework issue.  It is documented here so later
 * issues preserve the intent.
 */

#ifndef ZDBG_BP_H
#define ZDBG_BP_H

#include "zdbg.h"
#include "zdbg_target.h"

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
 *   - installed flag: whether an int3 byte is currently present
 *     in target memory at that address.  When a breakpoint is
 *     hit, the debugger restores the original byte, sets RIP
 *     back, and leaves the breakpoint logically enabled but
 *     uninstalled until the instruction has been stepped over.
 */

struct zbp {
	enum zbp_state state;
	zaddr_t addr;
	uint8_t orig;
	int temporary;
	int installed;
};

struct zbp_table {
	struct zbp bp[ZDBG_MAX_BREAKPOINTS];
};

void zbp_table_init(struct zbp_table *bt);
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
