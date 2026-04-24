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

/*
 * Windows image paths use backslash separators.  The basename
 * extraction inside zmaps_find_module() must handle them so
 * lookups like `KERNEL32.DLL` or `kernel32` match
 * `C:\Windows\System32\KERNEL32.DLL`.
 */
static void
test_find_module_backslash(void)
{
	struct zmap_table mt;
	const struct zmap *m;
	int amb;

	zmaps_init(&mt);
	mt.maps[0].start = 0x7ff612340000ULL;
	mt.maps[0].end = 0x7ff612360000ULL;
	mt.maps[0].offset = 0;
	strcpy(mt.maps[0].perms, "r-xp");
	strcpy(mt.maps[0].name,
	    "C:\\Windows\\System32\\KERNEL32.DLL");
	mt.count = 1;

	amb = 0;
	m = zmaps_find_module(&mt, "KERNEL32.DLL", &amb);
	if (m != &mt.maps[0])
		FAILF("KERNEL32.DLL basename should match backslash path");

#if defined(_WIN32)
	amb = 0;
	m = zmaps_find_module(&mt, "kernel32.dll", &amb);
	if (m != &mt.maps[0])
		FAILF("case-insensitive match expected on Windows");

	amb = 0;
	m = zmaps_find_module(&mt, "kernel32", &amb);
	if (m != &mt.maps[0])
		FAILF("prefix match 'kernel32' should hit KERNEL32.DLL "
		    "on Windows");
#endif
}

/*
 * zmaps_parse_line sets raw_file_offset_valid=1 for named
 * non-bracketed / non-deleted entries and leaves it 0 for
 * anonymous, bracketed and " (deleted)" entries.  This is the
 * gate used by zpatch_va_to_file.
 */
static void
test_parse_raw_file_offset_valid(void)
{
	struct zmap m;

	if (zmaps_parse_line(
	    "400000-401000 r-xp 00000000 08:02 1 /bin/ls\n", &m) != 0) {
		FAILF("parse file-backed");
		return;
	}
	if (!m.raw_file_offset_valid)
		FAILF("file-backed map should be raw_file_offset_valid");

	if (zmaps_parse_line(
	    "500000-501000 rw-p 00000000 00:00 0\n", &m) != 0) {
		FAILF("parse anon");
		return;
	}
	if (m.raw_file_offset_valid)
		FAILF("anonymous map must not be raw_file_offset_valid");

	if (zmaps_parse_line(
	    "600000-601000 rw-p 00000000 00:00 0 [heap]\n", &m) != 0) {
		FAILF("parse bracketed");
		return;
	}
	if (m.raw_file_offset_valid)
		FAILF("bracketed map must not be raw_file_offset_valid");

	if (zmaps_parse_line(
	    "700000-701000 r-xp 00000100 08:02 42 "
	    "/tmp/old (deleted)\n", &m) != 0) {
		FAILF("parse deleted");
		return;
	}
	if (m.raw_file_offset_valid)
		FAILF("deleted-file map must not be raw_file_offset_valid");
}

/*
 * Windows protection-to-perms helper test.  Compiled only on
 * Windows where zmaps_protect_to_perms is available.
 */
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

static void
expect_perms(uint32_t prot, const char *want, const char *desc)
{
	char got[5];
	zmaps_protect_to_perms(prot, got);
	if (strcmp(got, want) != 0)
		FAILF("%s: got '%s' want '%s' (prot=0x%08x)",
		    desc, got, want, (unsigned)prot);
}

static void
test_protect_to_perms(void)
{
	expect_perms(PAGE_NOACCESS,             "---p", "NOACCESS");
	expect_perms(PAGE_READONLY,              "r--p", "READONLY");
	expect_perms(PAGE_READWRITE,             "rw-p", "READWRITE");
	expect_perms(PAGE_WRITECOPY,             "rw-p", "WRITECOPY");
	expect_perms(PAGE_EXECUTE,               "--xp", "EXECUTE");
	expect_perms(PAGE_EXECUTE_READ,          "r-xp", "EXECUTE_READ");
	expect_perms(PAGE_EXECUTE_READWRITE,     "rwxp", "EXECUTE_READWRITE");
	expect_perms(PAGE_EXECUTE_WRITECOPY,     "rwxp", "EXECUTE_WRITECOPY");
	expect_perms(PAGE_GUARD | PAGE_READWRITE, "rw-g", "GUARD|RW");
	expect_perms(PAGE_NOCACHE | PAGE_READWRITE, "rw-p", "NOCACHE|RW");
}
#endif /* _WIN32 */

int
main(void)
{
	test_parse_ok();
	test_parse_exec();
	test_parse_anon();
	test_parse_bracketed();
	test_parse_bad();
	test_find_by_addr();
	test_find_module_backslash();
	test_parse_raw_file_offset_valid();
#if defined(_WIN32)
	test_protect_to_perms();
#endif

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_maps ok\n");
	return 0;
}
