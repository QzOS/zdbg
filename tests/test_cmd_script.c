/*
 * test_cmd_script.c - unit tests for command-script sourcing.
 *
 * These tests exercise zcmd_source_file()/zcmd_source_stream()
 * without a live target.  Scripts are written to temporary files
 * and executed against an initialised struct zdbg.  Only commands
 * that succeed without a target are used (?, q, source, blank
 * lines, comments, an unknown command for the failure path).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zdbg.h"
#include "zdbg_cmd.h"

#define CHECK(cond) \
	do { if (!(cond)) { printf("FAIL: %s:%d %s\n", __FILE__, \
	    __LINE__, #cond); return 1; } } while (0)

static int
write_script(const char *path, const char *contents)
{
	FILE *fp = fopen(path, "w");
	if (fp == NULL)
		return -1;
	if (fputs(contents, fp) == EOF) {
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 0;
}

static int
test_blank_and_comments(void)
{
	struct zdbg d;
	const char *path = "/tmp/zdbg_test_blank.zdbg";
	int rc;

	zdbg_init(&d);
	d.quiet = 1;
	CHECK(write_script(path,
	    "\n"
	    "; full-line comment\n"
	    "  ; comment after whitespace\n"
	    "# hash comment\n"
	    "    # hash after whitespace\n"
	    "\n"
	    "?\n") == 0);
	rc = zcmd_source_file(&d, path);
	CHECK(rc == 0);
	CHECK(d.had_error == 0);
	CHECK(d.quit_requested == 0);
	zdbg_fini(&d);
	remove(path);
	return 0;
}

static int
test_stops_on_failure(void)
{
	struct zdbg d;
	const char *path = "/tmp/zdbg_test_fail.zdbg";
	int rc;

	zdbg_init(&d);
	d.quiet = 1;
	CHECK(write_script(path,
	    "?\n"
	    "this_is_not_a_real_command\n"
	    "?\n") == 0);
	rc = zcmd_source_file(&d, path);
	CHECK(rc == -1);
	CHECK(d.had_error == 1);
	zdbg_fini(&d);
	remove(path);
	return 0;
}

static int
test_q_sets_quit(void)
{
	struct zdbg d;
	const char *path = "/tmp/zdbg_test_quit.zdbg";
	int rc;

	zdbg_init(&d);
	d.quiet = 1;
	CHECK(write_script(path,
	    "?\n"
	    "q\n"
	    "?\n") == 0);
	rc = zcmd_source_file(&d, path);
	CHECK(rc == 0);
	CHECK(d.quit_requested == 1);
	CHECK(d.had_error == 0);
	zdbg_fini(&d);
	remove(path);
	return 0;
}

static int
test_missing_file(void)
{
	struct zdbg d;
	int rc;

	zdbg_init(&d);
	d.quiet = 1;
	rc = zcmd_source_file(&d, "/tmp/zdbg_does_not_exist.zdbg");
	CHECK(rc == -2);
	zdbg_fini(&d);
	return 0;
}

static int
test_source_nesting_limit(void)
{
	struct zdbg d;
	const char *path = "/tmp/zdbg_test_nest.zdbg";
	char body[128];
	int rc;

	zdbg_init(&d);
	d.quiet = 1;
	snprintf(body, sizeof(body), "source %s\n", path);
	CHECK(write_script(path, body) == 0);
	rc = zcmd_source_file(&d, path);
	/* Recursion bottoms out with a setup error which propagates
	 * back up as a series of command failures. */
	CHECK(rc == -1);
	CHECK(d.had_error == 1);
	zdbg_fini(&d);
	remove(path);
	return 0;
}

static int
test_line_too_long(void)
{
	struct zdbg d;
	const char *path = "/tmp/zdbg_test_long.zdbg";
	FILE *fp;
	int i;
	int rc;

	zdbg_init(&d);
	d.quiet = 1;
	fp = fopen(path, "w");
	CHECK(fp != NULL);
	for (i = 0; i < 4096; i++)
		fputc('a', fp);
	fputc('\n', fp);
	fclose(fp);
	rc = zcmd_source_file(&d, path);
	CHECK(rc == -1);
	CHECK(d.had_error == 1);
	zdbg_fini(&d);
	remove(path);
	return 0;
}

static int
test_quoted_source_path(void)
{
	struct zdbg d;
	const char *target = "/tmp/zdbg test space.zdbg";
	const char *outer = "/tmp/zdbg_test_quoted.zdbg";
	int rc;

	zdbg_init(&d);
	d.quiet = 1;
	CHECK(write_script(target, "?\nq\n") == 0);
	CHECK(write_script(outer,
	    "source \"/tmp/zdbg test space.zdbg\"\n") == 0);
	rc = zcmd_source_file(&d, outer);
	CHECK(rc == 0);
	CHECK(d.quit_requested == 1);
	zdbg_fini(&d);
	remove(target);
	remove(outer);
	return 0;
}

int
main(void)
{
	int fails = 0;

	fails += test_blank_and_comments();
	fails += test_stops_on_failure();
	fails += test_q_sets_quit();
	fails += test_missing_file();
	fails += test_source_nesting_limit();
	fails += test_line_too_long();
	fails += test_quoted_source_path();

	if (fails == 0) {
		printf("test_cmd_script ok\n");
		return 0;
	}
	printf("test_cmd_script FAIL: %d failures\n", fails);
	return 1;
}
