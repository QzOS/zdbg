/*
 * test_check.c - unit tests for the script-friendly `check`
 * command family.
 *
 * Exercises behaviour that does not require a live target:
 *   - target-less failures
 *   - file existence / size assertions
 *   - last-stop tracking (check exited, check stop, check rip)
 *
 * Live-target paths (check reg/mem/symbol/map) are exercised by
 * the integration script examples and the OS-specific test
 * suites; here we keep things hermetic.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zdbg.h"
#include "zdbg_cmd.h"
#include "zdbg_target.h"

#define CHECK(cond) \
	do { if (!(cond)) { printf("FAIL: %s:%d %s\n", __FILE__, \
	    __LINE__, #cond); return 1; } } while (0)

static int
test_target_missing(void)
{
	struct zdbg d;

	zdbg_init(&d);
	d.quiet = 1;
	CHECK(zcmd_exec(&d, "check target") == -1);
	CHECK(zcmd_exec(&d, "check stopped") == -1);
	CHECK(zcmd_exec(&d, "check running") == -1);
	zdbg_fini(&d);
	return 0;
}

static int
test_unknown_subcommand(void)
{
	struct zdbg d;

	zdbg_init(&d);
	d.quiet = 1;
	CHECK(zcmd_exec(&d, "check") == -1);
	CHECK(zcmd_exec(&d, "check banana") == -1);
	zdbg_fini(&d);
	return 0;
}

static int
test_file_exists_and_size(void)
{
	struct zdbg d;
	const char *path = "/tmp/zdbg_test_check_file.bin";
	FILE *fp;

	zdbg_init(&d);
	d.quiet = 1;

	fp = fopen(path, "wb");
	CHECK(fp != NULL);
	CHECK(fwrite("hello!", 1, 6, fp) == 6);
	fclose(fp);

	{
		char cmd[256];
		snprintf(cmd, sizeof(cmd), "check file %s exists", path);
		CHECK(zcmd_exec(&d, cmd) == 0);
		snprintf(cmd, sizeof(cmd), "check file %s size 6", path);
		CHECK(zcmd_exec(&d, cmd) == 0);
		snprintf(cmd, sizeof(cmd), "check file %s size 7", path);
		CHECK(zcmd_exec(&d, cmd) == -1);
	}

	CHECK(zcmd_exec(&d,
	    "check file /tmp/zdbg_no_such_file_xyz exists") == -1);

	remove(path);
	zdbg_fini(&d);
	return 0;
}

static int
test_file_quoted_path(void)
{
	struct zdbg d;
	const char *path = "/tmp/zdbg test check space.bin";
	FILE *fp;

	zdbg_init(&d);
	d.quiet = 1;

	fp = fopen(path, "wb");
	CHECK(fp != NULL);
	CHECK(fwrite("ab", 1, 2, fp) == 2);
	fclose(fp);

	CHECK(zcmd_exec(&d,
	    "check file \"/tmp/zdbg test check space.bin\" exists") == 0);
	CHECK(zcmd_exec(&d,
	    "check file \"/tmp/zdbg test check space.bin\" size 2") == 0);

	remove(path);
	zdbg_fini(&d);
	return 0;
}

static int
test_no_last_stop(void)
{
	struct zdbg d;

	zdbg_init(&d);
	d.quiet = 1;
	CHECK(d.have_last_stop == 0);
	CHECK(zcmd_exec(&d, "check stop initial") == -1);
	CHECK(zcmd_exec(&d, "check exited") == -1);
	zdbg_fini(&d);
	return 0;
}

static int
test_last_stop_tracking(void)
{
	struct zdbg d;

	zdbg_init(&d);
	d.quiet = 1;

	/* Synthesize a stop record as the run loop would. */
	d.last_stop.reason = ZSTOP_EXIT;
	d.last_stop.code = 0;
	d.have_last_stop = 1;
	/* Pretend the target reached the EXITED state. */
	d.target.state = ZTARGET_EXITED;

	CHECK(zcmd_exec(&d, "check exited") == 0);
	CHECK(zcmd_exec(&d, "check exited 0") == 0);
	CHECK(zcmd_exec(&d, "check exited 1") == -1);
	CHECK(zcmd_exec(&d, "check stop exit") == 0);
	CHECK(zcmd_exec(&d, "check stop breakpoint") == -1);
	CHECK(zcmd_exec(&d, "check stop bogus") == -1);

	d.last_stop.reason = ZSTOP_BREAKPOINT;
	d.last_stop.addr = 0x1234;
	CHECK(zcmd_exec(&d, "check stop breakpoint") == 0);
	CHECK(zcmd_exec(&d, "check stop singlestep") == -1);
	CHECK(zcmd_exec(&d, "check stop hwbp") == -1); /* no hwbp slot */

	d.target.state = ZTARGET_EMPTY;
	zdbg_fini(&d);
	return 0;
}

static int
test_symbol_numeric_rejected(void)
{
	struct zdbg d;

	zdbg_init(&d);
	d.quiet = 1;
	/* Pure numeric input must not be accepted as a symbol name
	 * even when no symbol table is loaded. */
	CHECK(zcmd_exec(&d, "check symbol 401000") == -1);
	CHECK(zcmd_exec(&d, "check symbol 0x401000") == -1);
	CHECK(zcmd_exec(&d, "check nosymbol 401000") == -1);
	/* Non-numeric token but no symbols: nosymbol passes. */
	CHECK(zcmd_exec(&d, "check nosymbol main") == 0);
	zdbg_fini(&d);
	return 0;
}

static int
test_assert_alias(void)
{
	struct zdbg d;

	zdbg_init(&d);
	d.quiet = 1;
	CHECK(zcmd_exec(&d, "assert target") == -1);
	CHECK(zcmd_exec(&d, "expect target") == -1);
	zdbg_fini(&d);
	return 0;
}

int
main(void)
{
	int fails = 0;

	fails += test_target_missing();
	fails += test_unknown_subcommand();
	fails += test_file_exists_and_size();
	fails += test_file_quoted_path();
	fails += test_no_last_stop();
	fails += test_last_stop_tracking();
	fails += test_symbol_numeric_rejected();
	fails += test_assert_alias();

	if (fails == 0) {
		printf("test_check ok\n");
		return 0;
	}
	printf("test_check FAIL: %d failures\n", fails);
	return 1;
}
