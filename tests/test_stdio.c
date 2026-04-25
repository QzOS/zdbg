/*
 * test_stdio.c - unit tests for target stdio configuration helpers.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_stdio.h"

#define FAIL(msg) do { fprintf(stderr, "FAIL: %s\n", msg); return 1; } while (0)

static int
test_default_inherit(void)
{
	struct zstdio_config c;

	zstdio_config_init(&c);
	if (c.in.mode != ZSTDIO_INHERIT) FAIL("stdin not inherit");
	if (c.out.mode != ZSTDIO_INHERIT) FAIL("stdout not inherit");
	if (c.err.mode != ZSTDIO_INHERIT) FAIL("stderr not inherit");
	if (c.in.path[0] != 0) FAIL("stdin path nonempty");
	return 0;
}

static int
test_set_file(void)
{
	struct zstdio_config c;

	zstdio_config_init(&c);
	if (zstdio_set_file(&c.in, "input.txt") != 0)
		FAIL("set_file failed");
	if (c.in.mode != ZSTDIO_FILE) FAIL("mode not FILE");
	if (strcmp(c.in.path, "input.txt") != 0) FAIL("path not stored");
	if (zstdio_set_file(&c.in, "") == 0) FAIL("empty path accepted");
	if (zstdio_set_file(&c.in, NULL) == 0) FAIL("null path accepted");
	return 0;
}

static int
test_capture(void)
{
	struct zstdio_slot s;
	const char *p;

	memset(&s, 0, sizeof(s));
	if (zstdio_set_capture(&s, "stdout") != 0)
		FAIL("capture failed");
	if (s.mode != ZSTDIO_CAPTURE) FAIL("mode not CAPTURE");
	if (s.path[0] == 0) FAIL("capture path empty");
	p = zstdio_slot_path(&s);
	if (p == NULL || strcmp(p, s.path) != 0)
		FAIL("slot_path mismatch");
	return 0;
}

static int
test_capture_unique(void)
{
	struct zstdio_slot a, b;

	memset(&a, 0, sizeof(a));
	memset(&b, 0, sizeof(b));
	if (zstdio_set_capture(&a, "stdout") != 0) FAIL("a fail");
	if (zstdio_set_capture(&b, "stdout") != 0) FAIL("b fail");
	if (strcmp(a.path, b.path) == 0) FAIL("paths not unique");
	return 0;
}

static int
test_stderr_to_stdout(void)
{
	struct zstdio_config c;

	zstdio_config_init(&c);
	if (zstdio_set_stdout(&c.err) != 0) FAIL("set_stdout failed");
	if (c.err.mode != ZSTDIO_STDOUT) FAIL("err mode not STDOUT");
	return 0;
}

static int
test_reset(void)
{
	struct zstdio_config c;

	zstdio_config_init(&c);
	(void)zstdio_set_file(&c.out, "/tmp/out.txt");
	(void)zstdio_set_null(&c.in);
	(void)zstdio_set_stdout(&c.err);
	zstdio_config_reset(&c);
	if (c.in.mode != ZSTDIO_INHERIT) FAIL("reset stdin");
	if (c.out.mode != ZSTDIO_INHERIT) FAIL("reset stdout");
	if (c.err.mode != ZSTDIO_INHERIT) FAIL("reset stderr");
	if (c.out.path[0] != 0) FAIL("reset path not cleared");
	return 0;
}

static int
test_null_path(void)
{
	const char *p;

	p = zstdio_null_path();
	if (p == NULL) FAIL("null_path null");
#if defined(_WIN32)
	if (strcmp(p, "NUL") != 0) FAIL("win null mismatch");
#else
	if (strcmp(p, "/dev/null") != 0) FAIL("posix null mismatch");
#endif
	return 0;
}

static int
test_describe(void)
{
	struct zstdio_slot s;
	char buf[ZDBG_STDIO_PATH_MAX + 64];

	memset(&s, 0, sizeof(s));
	zstdio_describe(&s, buf, sizeof(buf));
	if (strcmp(buf, "inherit") != 0) FAIL("describe inherit");

	(void)zstdio_set_null(&s);
	zstdio_describe(&s, buf, sizeof(buf));
	if (strcmp(buf, "null") != 0) FAIL("describe null");

	(void)zstdio_set_file(&s, "x.txt");
	zstdio_describe(&s, buf, sizeof(buf));
	if (strcmp(buf, "file x.txt") != 0) FAIL("describe file");

	(void)zstdio_set_stdout(&s);
	zstdio_describe(&s, buf, sizeof(buf));
	if (strcmp(buf, "stdout") != 0) FAIL("describe stdout");

	return 0;
}

static int
test_slot_path(void)
{
	struct zstdio_slot s;

	memset(&s, 0, sizeof(s));
	if (zstdio_slot_path(&s) != NULL) FAIL("inherit path nonnull");
	(void)zstdio_set_null(&s);
	if (zstdio_slot_path(&s) != NULL) FAIL("null path nonnull");
	(void)zstdio_set_file(&s, "x");
	if (zstdio_slot_path(&s) == NULL) FAIL("file path null");
	return 0;
}

int
main(void)
{
	if (test_default_inherit() != 0) return 1;
	if (test_set_file() != 0) return 1;
	if (test_capture() != 0) return 1;
	if (test_capture_unique() != 0) return 1;
	if (test_stderr_to_stdout() != 0) return 1;
	if (test_reset() != 0) return 1;
	if (test_null_path() != 0) return 1;
	if (test_describe() != 0) return 1;
	if (test_slot_path() != 0) return 1;
	printf("test_stdio ok\n");
	return 0;
}
