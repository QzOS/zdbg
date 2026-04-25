/*
 * test_actions.c - unit tests for the action-list data
 * structure.  No live target needed; the structure is pure data
 * and the allow-list lookup is a small string compare.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_actions.h"

#define CHECK(cond) \
	do { if (!(cond)) { printf("FAIL: %s:%d %s\n", __FILE__, \
	    __LINE__, #cond); return 1; } } while (0)

static int
test_init_zero(void)
{
	struct zaction_list a;

	memset(&a, 0xa5, sizeof(a));
	zactions_init(&a);
	CHECK(a.count == 0);
	CHECK(a.silent == 0);
	CHECK(a.lines[0][0] == 0);
	return 0;
}

static int
test_add_until_full(void)
{
	struct zaction_list a;
	int i;

	zactions_init(&a);
	for (i = 0; i < ZDBG_MAX_ACTIONS; i++)
		CHECK(zactions_add(&a, "printf x") == 0);
	CHECK(a.count == ZDBG_MAX_ACTIONS);
	CHECK(zactions_add(&a, "printf y") == -1);
	CHECK(a.count == ZDBG_MAX_ACTIONS);
	return 0;
}

static int
test_too_long_rejected(void)
{
	struct zaction_list a;
	char big[ZDBG_ACTION_LINE_MAX + 16];

	memset(big, 'x', sizeof(big) - 1);
	big[sizeof(big) - 1] = 0;
	zactions_init(&a);
	CHECK(zactions_add(&a, big) == -1);
	CHECK(a.count == 0);
	/* exactly max-1 fits */
	memset(big, 'y', ZDBG_ACTION_LINE_MAX - 1);
	big[ZDBG_ACTION_LINE_MAX - 1] = 0;
	CHECK(zactions_add(&a, big) == 0);
	CHECK(a.count == 1);
	/* empty line rejected */
	CHECK(zactions_add(&a, "") == -1);
	return 0;
}

static int
test_del_shifts(void)
{
	struct zaction_list a;

	zactions_init(&a);
	CHECK(zactions_add(&a, "one") == 0);
	CHECK(zactions_add(&a, "two") == 0);
	CHECK(zactions_add(&a, "three") == 0);
	CHECK(a.count == 3);
	CHECK(zactions_del(&a, 0) == 0);
	CHECK(a.count == 2);
	CHECK(strcmp(a.lines[0], "two") == 0);
	CHECK(strcmp(a.lines[1], "three") == 0);
	CHECK(zactions_del(&a, 5) == -1);
	CHECK(zactions_del(&a, 1) == 0);
	CHECK(a.count == 1);
	CHECK(strcmp(a.lines[0], "two") == 0);
	return 0;
}

static int
test_set_replaces(void)
{
	struct zaction_list a;

	zactions_init(&a);
	CHECK(zactions_add(&a, "old") == 0);
	CHECK(zactions_set(&a, 0, "new") == 0);
	CHECK(strcmp(a.lines[0], "new") == 0);
	CHECK(zactions_set(&a, 1, "out") == -1);
	CHECK(zactions_set(&a, 0, "") == -1);
	return 0;
}

static int
test_clear_resets(void)
{
	struct zaction_list a;

	zactions_init(&a);
	zactions_set_silent(&a, 1);
	(void)zactions_add(&a, "printf hi");
	CHECK(a.count == 1);
	CHECK(a.silent == 1);
	zactions_clear(&a);
	CHECK(a.count == 0);
	CHECK(a.silent == 0);
	return 0;
}

static int
test_silent_flag(void)
{
	struct zaction_list a;

	zactions_init(&a);
	CHECK(a.silent == 0);
	zactions_set_silent(&a, 1);
	CHECK(a.silent == 1);
	zactions_set_silent(&a, 0);
	CHECK(a.silent == 0);
	zactions_set_silent(&a, 42);
	CHECK(a.silent == 1);
	return 0;
}

static int
test_continue_keyword(void)
{
	CHECK(zactions_is_continue("continue"));
	CHECK(zactions_is_continue("cont"));
	CHECK(zactions_is_continue("  continue  "));
	CHECK(zactions_is_continue("CONTINUE"));
	CHECK(!zactions_is_continue("continues"));
	CHECK(!zactions_is_continue("printf cont"));
	CHECK(!zactions_is_continue(""));
	CHECK(!zactions_is_continue(NULL));
	return 0;
}

static int
test_allowed(void)
{
	CHECK(zactions_is_allowed("printf hi"));
	CHECK(zactions_is_allowed("r"));
	CHECK(zactions_is_allowed("R"));
	CHECK(zactions_is_allowed("d rsp 20"));
	CHECK(zactions_is_allowed("bt"));
	CHECK(zactions_is_allowed("check rip main"));
	CHECK(zactions_is_allowed("hits b 0"));
	CHECK(zactions_is_allowed("b"));
	CHECK(zactions_is_allowed("continue"));
	CHECK(zactions_is_allowed("cont"));
	CHECK(zactions_is_allowed("silent"));

	/* `b ADDR` would create a breakpoint mid-stop */
	CHECK(!zactions_is_allowed("b main"));

	/* explicit disallow list samples */
	CHECK(!zactions_is_allowed("g"));
	CHECK(!zactions_is_allowed("t"));
	CHECK(!zactions_is_allowed("p"));
	CHECK(!zactions_is_allowed("bc 0"));
	CHECK(!zactions_is_allowed("bd 0"));
	CHECK(!zactions_is_allowed("hb main"));
	CHECK(!zactions_is_allowed("cond b 0 1"));
	CHECK(!zactions_is_allowed("ignore b 0 5"));
	CHECK(!zactions_is_allowed("actions b 0 clear"));
	CHECK(!zactions_is_allowed("commands b 0"));
	CHECK(!zactions_is_allowed("source x"));
	CHECK(!zactions_is_allowed("e 1000 90"));
	CHECK(!zactions_is_allowed("pa 1000 1 nop"));
	CHECK(!zactions_is_allowed("sig SIGSEGV"));
	CHECK(!zactions_is_allowed(""));
	CHECK(!zactions_is_allowed("   "));
	return 0;
}

int
main(void)
{
	int rc = 0;

	rc |= test_init_zero();
	rc |= test_add_until_full();
	rc |= test_too_long_rejected();
	rc |= test_del_shifts();
	rc |= test_set_replaces();
	rc |= test_clear_resets();
	rc |= test_silent_flag();
	rc |= test_continue_keyword();
	rc |= test_allowed();
	if (rc == 0)
		printf("test_actions ok\n");
	return rc ? 1 : 0;
}
