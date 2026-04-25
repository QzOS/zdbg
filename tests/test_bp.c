/*
 * test_bp.c - non-ptrace unit tests for the breakpoint table.
 *
 * These tests only exercise bookkeeping paths that do not need a
 * live target: alloc/find, clear of an uninstalled breakpoint,
 * and state/installed distinction after clear.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_arch.h"
#include "zdbg_bp.h"
#include "zdbg_target.h"

#define CHECK(cond) \
	do { if (!(cond)) { printf("FAIL: %s:%d %s\n", __FILE__, \
	    __LINE__, #cond); return 1; } } while (0)

static int
test_alloc_defaults(void)
{
	struct zbp_table bt;
	int id;

	zbp_table_init(&bt, zarch_x86_64());
	id = zbp_alloc(&bt, 0x400000, 0);
	CHECK(id == 0);
	CHECK(bt.bp[id].state == ZBP_DISABLED);
	CHECK(bt.bp[id].installed == 0);
	CHECK(bt.bp[id].temporary == 0);
	CHECK(bt.bp[id].addr == 0x400000);
	return 0;
}

static int
test_alloc_reuses_same_addr(void)
{
	struct zbp_table bt;
	int a, b;

	zbp_table_init(&bt, zarch_x86_64());
	a = zbp_alloc(&bt, 0x401000, 0);
	b = zbp_alloc(&bt, 0x401000, 1);
	CHECK(a == b);
	return 0;
}

static int
test_find_by_addr(void)
{
	struct zbp_table bt;
	int id;

	zbp_table_init(&bt, zarch_x86_64());
	CHECK(zbp_find_by_addr(&bt, 0x401000) < 0);
	id = zbp_alloc(&bt, 0x401000, 0);
	CHECK(zbp_find_by_addr(&bt, 0x401000) == id);
	CHECK(zbp_find_by_addr(&bt, 0x402000) < 0);
	return 0;
}

static int
test_clear_uninstalled_does_not_touch_target(void)
{
	struct zbp_table bt;
	struct ztarget dummy;
	int id;

	/*
	 * An all-zero ztarget has state == ZTARGET_EMPTY, so any
	 * attempt to write memory would take the uninstall path,
	 * fail, and (before this change) bubble up as an error.
	 * With installed=0 bookkeeping the clear must succeed
	 * without touching the target at all.
	 */
	memset(&dummy, 0, sizeof(dummy));
	zbp_table_init(&bt, zarch_x86_64());
	id = zbp_alloc(&bt, 0x401000, 0);
	CHECK(bt.bp[id].installed == 0);
	CHECK(zbp_clear(&dummy, &bt, id) == 0);
	CHECK(bt.bp[id].state == ZBP_EMPTY);
	return 0;
}

static int
test_install_requires_enabled(void)
{
	struct zbp_table bt;
	struct ztarget dummy;
	int id;

	memset(&dummy, 0, sizeof(dummy));
	zbp_table_init(&bt, zarch_x86_64());
	id = zbp_alloc(&bt, 0x401000, 0);
	/* state is ZBP_DISABLED, install must refuse */
	CHECK(zbp_install(&dummy, &bt, id) < 0);
	CHECK(bt.bp[id].installed == 0);
	return 0;
}

static int
test_handle_trap_ignores_zero_rip(void)
{
	struct zbp_table bt;
	struct ztarget dummy;
	struct zregs regs;
	int id = -2;

	memset(&dummy, 0, sizeof(dummy));
	memset(&regs, 0, sizeof(regs));
	zbp_table_init(&bt, zarch_x86_64());
	regs.rip = 0;
	CHECK(zbp_handle_trap(&dummy, &bt, &regs, &id) == 0);
	CHECK(id == -1);
	return 0;
}

static int
test_handle_trap_no_match(void)
{
	struct zbp_table bt;
	struct ztarget dummy;
	struct zregs regs;
	int id = -2;

	memset(&dummy, 0, sizeof(dummy));
	memset(&regs, 0, sizeof(regs));
	zbp_table_init(&bt, zarch_x86_64());
	regs.rip = 0x401234;
	CHECK(zbp_handle_trap(&dummy, &bt, &regs, &id) == 0);
	CHECK(id == -1);
	return 0;
}

static int
test_handle_trap_ignores_uninstalled_match(void)
{
	struct zbp_table bt;
	struct ztarget dummy;
	struct zregs regs;
	int id = -2;
	int a;

	memset(&dummy, 0, sizeof(dummy));
	memset(&regs, 0, sizeof(regs));
	zbp_table_init(&bt, zarch_x86_64());
	a = zbp_alloc(&bt, 0x401233, 0);
	/* logically enabled but not installed: must not claim trap */
	bt.bp[a].state = ZBP_ENABLED;
	bt.bp[a].installed = 0;
	regs.rip = 0x401234;
	CHECK(zbp_handle_trap(&dummy, &bt, &regs, &id) == 0);
	CHECK(id == -1);
	return 0;
}

static int
test_list_handles_enabled_and_installed_separately(void)
{
	struct zbp_table bt;
	int a, b;

	zbp_table_init(&bt, zarch_x86_64());
	a = zbp_alloc(&bt, 0x401000, 0);
	b = zbp_alloc(&bt, 0x402000, 0);
	bt.bp[a].state = ZBP_ENABLED;
	bt.bp[a].installed = 1;
	bt.bp[b].state = ZBP_ENABLED;
	bt.bp[b].installed = 0;
	CHECK(bt.bp[a].state == ZBP_ENABLED && bt.bp[a].installed == 1);
	CHECK(bt.bp[b].state == ZBP_ENABLED && bt.bp[b].installed == 0);
	/* smoke: must not crash */
	zbp_list(&bt);
	return 0;
}

static int
test_alloc_resets_orig_storage(void)
{
	struct zbp_table bt;
	int id;

	zbp_table_init(&bt, zarch_x86_64());
	id = zbp_alloc(&bt, 0x400000, 0);
	CHECK(id >= 0);
	/* Newly allocated slots must not claim any saved original
	 * bytes; orig_len stays zero until install() records them. */
	CHECK(bt.bp[id].orig_len == 0);
	{
		size_t k;
		for (k = 0; k < sizeof(bt.bp[id].orig); k++)
			CHECK(bt.bp[id].orig[k] == 0);
	}
	return 0;
}

int
main(void)
{
	if (test_alloc_defaults()) return 1;
	if (test_alloc_reuses_same_addr()) return 1;
	if (test_find_by_addr()) return 1;
	if (test_clear_uninstalled_does_not_touch_target()) return 1;
	if (test_install_requires_enabled()) return 1;
	if (test_handle_trap_ignores_zero_rip()) return 1;
	if (test_handle_trap_no_match()) return 1;
	if (test_handle_trap_ignores_uninstalled_match()) return 1;
	if (test_list_handles_enabled_and_installed_separately()) return 1;
	if (test_alloc_resets_orig_storage()) return 1;
	printf("OK\n");
	return 0;
}
