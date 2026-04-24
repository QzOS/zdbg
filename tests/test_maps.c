/*
 * test_maps.c - /proc/<pid>/maps line parser tests and module
 * lookup tests for zmap_table.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_maps.h"

static int failures;

#define FAILF(...) do {                                               \
	fprintf(stderr, "FAIL %s:%d ", __FILE__, __LINE__);           \
	fprintf(stderr, __VA_ARGS__);                                 \
	fprintf(stderr, "\n");                                        \
	failures++;                                                   \
} while (0)

static void
test_parse_ok(void)
{
	struct zmap m;
	const char *line =
	    "555555554000-555555555000 r--p 00000000 08:02 123456 "
	    "/home/me/prog\n";
	if (zmaps_parse_line(line, &m) != 0) {
		FAILF("parse failed");
		return;
	}
	if (m.start != 0x555555554000ULL || m.end != 0x555555555000ULL)
		FAILF("start/end: %llx-%llx",
		    (unsigned long long)m.start,
		    (unsigned long long)m.end);
	if (m.offset != 0x0)
		FAILF("offset: %llx", (unsigned long long)m.offset);
	if (strcmp(m.perms, "r--p") != 0)
		FAILF("perms: '%s'", m.perms);
	if (strcmp(m.name, "/home/me/prog") != 0)
		FAILF("name: '%s'", m.name);
}

static void
test_parse_exec(void)
{
	struct zmap m;
	const char *line =
	    "7ffff7dd0000-7ffff7f9b000 r-xp 00026000 08:02 42 "
	    "/lib/x86_64-linux-gnu/libc.so.6";
	if (zmaps_parse_line(line, &m) != 0) {
		FAILF("parse failed");
		return;
	}
	if (m.offset != 0x26000)
		FAILF("offset: %llx", (unsigned long long)m.offset);
	if (strcmp(m.perms, "r-xp") != 0)
		FAILF("perms: '%s'", m.perms);
	if (strcmp(m.name, "/lib/x86_64-linux-gnu/libc.so.6") != 0)
		FAILF("name: '%s'", m.name);
}

static void
test_parse_anon(void)
{
	struct zmap m;
	const char *line =
	    "7ffff7ffc000-7ffff7fff000 rw-p 00000000 00:00 0\n";
	if (zmaps_parse_line(line, &m) != 0) {
		FAILF("parse failed");
		return;
	}
	if (m.name[0] != 0)
		FAILF("expected empty name, got '%s'", m.name);
}

static void
test_parse_bracketed(void)
{
	struct zmap m;
	const char *line =
	    "7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0 [stack]\n";
	if (zmaps_parse_line(line, &m) != 0) {
		FAILF("parse failed");
		return;
	}
	if (strcmp(m.name, "[stack]") != 0)
		FAILF("name: '%s'", m.name);
}

static void
test_parse_bad(void)
{
	struct zmap m;
	if (zmaps_parse_line("", &m) == 0)
		FAILF("empty parsed ok");
	if (zmaps_parse_line("garbage\n", &m) == 0)
		FAILF("garbage parsed ok");
	if (zmaps_parse_line("1000-", &m) == 0)
		FAILF("truncated parsed ok");
}

static void
test_find_by_addr(void)
{
	struct zmap_table mt;
	const char *a =
	    "400000-401000 r--p 00000000 08:02 1 /p\n";
	const char *b =
	    "401000-402000 r-xp 00001000 08:02 1 /p\n";

	zmaps_init(&mt);
	if (zmaps_parse_line(a, &mt.maps[mt.count]) != 0) {
		FAILF("parse a");
		return;
	}
	mt.count++;
	if (zmaps_parse_line(b, &mt.maps[mt.count]) != 0) {
		FAILF("parse b");
		return;
	}
	mt.count++;

	if (zmaps_find_by_addr(&mt, 0x400100) != &mt.maps[0])
		FAILF("find addr 0x400100");
	if (zmaps_find_by_addr(&mt, 0x401fff) != &mt.maps[1])
		FAILF("find addr 0x401fff");
	if (zmaps_find_by_addr(&mt, 0x500000) != NULL)
		FAILF("find oob should fail");
}

int
main(void)
{
	test_parse_ok();
	test_parse_exec();
	test_parse_anon();
	test_parse_bracketed();
	test_parse_bad();
	test_find_by_addr();

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_maps ok\n");
	return 0;
}
