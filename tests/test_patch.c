/*
 * test_patch.c - patch journal and VA-to-file mapping tests.
 *
 * Covers:
 *  - zpatch_table_init
 *  - zpatch_record stores addr/len/bytes/origin and states
 *  - zpatch_record rejects too-large patches
 *  - zpatch_find_overlap detects byte overlap
 *  - zpatch_mark_reverted/applied state transitions
 *  - zpatch_va_to_file success, anonymous-map rejection,
 *    bracketed-map rejection, deleted-mapping rejection,
 *    and multi-mapping span rejection
 *  - conservative on-disk patch write: accepts matching old
 *    bytes, refuses mismatched old bytes
 */

#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#include "zdbg_patch.h"
#include "zdbg_maps.h"

static int failures;

#define FAILF(...) do {                                               \
	fprintf(stderr, "FAIL %s:%d ", __FILE__, __LINE__);           \
	fprintf(stderr, __VA_ARGS__);                                 \
	fprintf(stderr, "\n");                                        \
	failures++;                                                   \
} while (0)

static void
test_init(void)
{
	struct zpatch_table pt;
	int i;

	zpatch_table_init(&pt);
	for (i = 0; i < ZDBG_MAX_PATCHES; i++) {
		if (pt.patches[i].state != ZPATCH_EMPTY)
			FAILF("slot %d not empty after init", i);
	}
}

static void
test_record_basic(void)
{
	struct zpatch_table pt;
	uint8_t oldb[3] = { 0x90, 0x90, 0x90 };
	uint8_t newb[3] = { 0xcc, 0xcc, 0xcc };
	const struct zpatch *p = NULL;
	int id;

	zpatch_table_init(&pt);
	id = zpatch_record(&pt, 0x1000, oldb, newb, 3, "pa");
	if (id < 0) {
		FAILF("record failed");
		return;
	}
	if (zpatch_get(&pt, id, &p) != 0 || p == NULL) {
		FAILF("get failed");
		return;
	}
	if (p->state != ZPATCH_APPLIED)
		FAILF("state not applied");
	if (p->addr != 0x1000 || p->len != 3)
		FAILF("addr/len");
	if (memcmp(p->old_bytes, oldb, 3) != 0)
		FAILF("old bytes");
	if (memcmp(p->new_bytes, newb, 3) != 0)
		FAILF("new bytes");
	if (strcmp(p->origin, "pa") != 0)
		FAILF("origin '%s'", p->origin);
	if (p->has_file != 0)
		FAILF("has_file should be 0");
}

static void
test_record_too_large(void)
{
	struct zpatch_table pt;
	uint8_t buf[ZDBG_PATCH_MAX_BYTES + 16];
	int id;

	memset(buf, 0, sizeof(buf));
	zpatch_table_init(&pt);
	id = zpatch_record(&pt, 0x1000, buf, buf, sizeof(buf), "e");
	if (id >= 0)
		FAILF("record should reject >max");

	id = zpatch_record(&pt, 0x1000, buf, buf, 0, "e");
	if (id >= 0)
		FAILF("record should reject len=0");
}

static void
test_overlap(void)
{
	struct zpatch_table pt;
	uint8_t b[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	int id0;

	zpatch_table_init(&pt);
	id0 = zpatch_record(&pt, 0x2000, b, b, 4, "e");
	if (id0 < 0) {
		FAILF("record 0");
		return;
	}
	if (zpatch_find_overlap(&pt, 0x2000, 2) != id0)
		FAILF("expected overlap at same start");
	if (zpatch_find_overlap(&pt, 0x2003, 2) != id0)
		FAILF("expected overlap at tail");
	if (zpatch_find_overlap(&pt, 0x2004, 2) != -1)
		FAILF("no overlap expected past end");
	if (zpatch_find_overlap(&pt, 0x1ff8, 4) != -1)
		FAILF("no overlap expected before start");
}

static void
test_state_transitions(void)
{
	struct zpatch_table pt;
	uint8_t o[1] = { 0x11 };
	uint8_t n[1] = { 0x22 };
	int id;
	const struct zpatch *p = NULL;

	zpatch_table_init(&pt);
	id = zpatch_record(&pt, 0x3000, o, n, 1, "e");
	if (id < 0) {
		FAILF("record");
		return;
	}
	if (zpatch_mark_reverted(&pt, id) != 0)
		FAILF("mark_reverted");
	(void)zpatch_get(&pt, id, &p);
	if (p == NULL || p->state != ZPATCH_REVERTED)
		FAILF("not reverted");
	if (zpatch_mark_reverted(&pt, id) == 0)
		FAILF("double revert should fail");
	if (zpatch_mark_applied(&pt, id) != 0)
		FAILF("mark_applied");
	(void)zpatch_get(&pt, id, &p);
	if (p == NULL || p->state != ZPATCH_APPLIED)
		FAILF("not applied again");
	if (zpatch_mark_applied(&pt, id) == 0)
		FAILF("double apply should fail");
}

/* Hand-build a map table for VA-to-file tests. */
static void
build_maps(struct zmap_table *mt)
{
	zmaps_init(mt);
	mt->count = 0;

	/* file-backed exec */
	mt->maps[mt->count].start = 0x400000;
	mt->maps[mt->count].end = 0x401000;
	mt->maps[mt->count].offset = 0x1000;
	strcpy(mt->maps[mt->count].perms, "r-xp");
	strcpy(mt->maps[mt->count].name, "/tmp/zdbg_test_prog");
	mt->count++;

	/* file-backed adjacent */
	mt->maps[mt->count].start = 0x401000;
	mt->maps[mt->count].end = 0x402000;
	mt->maps[mt->count].offset = 0x2000;
	strcpy(mt->maps[mt->count].perms, "r--p");
	strcpy(mt->maps[mt->count].name, "/tmp/zdbg_test_prog");
	mt->count++;

	/* anonymous */
	mt->maps[mt->count].start = 0x500000;
	mt->maps[mt->count].end = 0x501000;
	mt->maps[mt->count].offset = 0;
	strcpy(mt->maps[mt->count].perms, "rw-p");
	mt->maps[mt->count].name[0] = 0;
	mt->count++;

	/* bracketed */
	mt->maps[mt->count].start = 0x600000;
	mt->maps[mt->count].end = 0x601000;
	mt->maps[mt->count].offset = 0;
	strcpy(mt->maps[mt->count].perms, "rw-p");
	strcpy(mt->maps[mt->count].name, "[stack]");
	mt->count++;

	/* deleted-file */
	mt->maps[mt->count].start = 0x700000;
	mt->maps[mt->count].end = 0x701000;
	mt->maps[mt->count].offset = 0x100;
	strcpy(mt->maps[mt->count].perms, "r-xp");
	strcpy(mt->maps[mt->count].name, "/tmp/oldprog (deleted)");
	mt->count++;
}

static void
test_va_to_file(void)
{
	struct zmap_table mt;
	char file[256];
	uint64_t off;

	build_maps(&mt);

	off = 0;
	if (zpatch_va_to_file(&mt, 0x400100, 4, file, sizeof(file), &off)
	    != 0)
		FAILF("file mapping should succeed");
	if (strcmp(file, "/tmp/zdbg_test_prog") != 0)
		FAILF("file '%s'", file);
	if (off != 0x1100)
		FAILF("off 0x%llx", (unsigned long long)off);

	if (zpatch_va_to_file(&mt, 0x500000, 4, file, sizeof(file), &off)
	    == 0)
		FAILF("anonymous map should be rejected");

	if (zpatch_va_to_file(&mt, 0x600100, 4, file, sizeof(file), &off)
	    == 0)
		FAILF("bracketed map should be rejected");

	if (zpatch_va_to_file(&mt, 0x700100, 4, file, sizeof(file), &off)
	    == 0)
		FAILF("deleted-file map should be rejected");

	/* spans two mappings */
	if (zpatch_va_to_file(&mt, 0x400ffe, 8, file, sizeof(file), &off)
	    == 0)
		FAILF("range spanning two mappings should be rejected");

	/* no mapping at all */
	if (zpatch_va_to_file(&mt, 0x900000, 4, file, sizeof(file), &off)
	    == 0)
		FAILF("unmapped addr should fail");
}

static void
test_resolve_file(void)
{
	struct zmap_table mt;
	struct zpatch p;
	uint8_t o[1] = { 0 };
	uint8_t n[1] = { 0 };
	struct zpatch_table pt;
	int id;

	build_maps(&mt);
	zpatch_table_init(&pt);

	id = zpatch_record(&pt, 0x400200, o, n, 1, "e");
	if (id < 0) {
		FAILF("record");
		return;
	}
	if (zpatch_resolve_file(&pt.patches[id], &mt) != 0)
		FAILF("resolve_file failed");
	if (!pt.patches[id].has_file)
		FAILF("has_file not set");
	if (pt.patches[id].file_off != 0x1200)
		FAILF("file_off 0x%llx",
		    (unsigned long long)pt.patches[id].file_off);

	/* anon -> resolve should fail cleanly */
	memset(&p, 0, sizeof(p));
	p.addr = 0x500100;
	p.len = 4;
	if (zpatch_resolve_file(&p, &mt) == 0)
		FAILF("anonymous should not resolve");
	if (p.has_file != 0)
		FAILF("has_file should be 0 after failure");
}

/*
 * Exercise the "pw" semantics: a temp file with known bytes,
 * then open/read/compare/write as write_patch_to_file does.
 * We mirror the logic here because the real function lives in
 * cmd.c and is static; the test keeps the behaviour documented.
 */
static int
file_read_at(const char *path, uint64_t off, uint8_t *buf, size_t len)
{
	FILE *f = fopen(path, "rb");
	size_t r;
	if (f == NULL)
		return -1;
	if (fseek(f, (long)off, SEEK_SET) != 0) {
		fclose(f);
		return -1;
	}
	r = fread(buf, 1, len, f);
	fclose(f);
	return r == len ? 0 : -1;
}

static int
file_write_at(const char *path, uint64_t off, const uint8_t *buf,
    size_t len)
{
	FILE *f = fopen(path, "wb");
	size_t w;
	if (f == NULL)
		return -1;
	(void)off;
	w = fwrite(buf, 1, len, f);
	fclose(f);
	return w == len ? 0 : -1;
}

/* Simulated pw path: refuse if on-disk bytes differ from old. */
static int
sim_pw(const char *path, uint64_t off, const uint8_t *oldb,
    const uint8_t *newb, size_t len)
{
	FILE *f;
	uint8_t cur[ZDBG_PATCH_MAX_BYTES];
	size_t r;

	f = fopen(path, "r+b");
	if (f == NULL)
		return -1;
	if (fseek(f, (long)off, SEEK_SET) != 0) {
		fclose(f);
		return -1;
	}
	r = fread(cur, 1, len, f);
	if (r != len) {
		fclose(f);
		return -1;
	}
	if (memcmp(cur, oldb, len) != 0) {
		fclose(f);
		return -2;	/* mismatch */
	}
	if (fseek(f, (long)off, SEEK_SET) != 0) {
		fclose(f);
		return -1;
	}
	if (fwrite(newb, 1, len, f) != len) {
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

static void
test_file_write_match(void)
{
#if defined(_WIN32)
	/* mkstemp is POSIX; skip on Windows. */
	return;
#else
	char tpl[] = "/tmp/zdbg_patch_test_XXXXXX";
	int fd;
	uint8_t base[16];
	uint8_t oldb[4];
	uint8_t newb[4];
	uint8_t check[4];
	size_t i;

	for (i = 0; i < sizeof(base); i++)
		base[i] = (uint8_t)(0x10 + i);
	/* the patch targets bytes [4..7] */
	memcpy(oldb, &base[4], 4);
	newb[0] = 0xAA;
	newb[1] = 0xBB;
	newb[2] = 0xCC;
	newb[3] = 0xDD;

	fd = mkstemp(tpl);
	if (fd < 0) {
		fprintf(stderr, "mkstemp failed; skipping file test\n");
		return;
	}
	close(fd);

	if (file_write_at(tpl, 0, base, sizeof(base)) < 0) {
		FAILF("seed temp file");
		remove(tpl);
		return;
	}

	/* matching old bytes -> write succeeds */
	if (sim_pw(tpl, 4, oldb, newb, 4) != 0)
		FAILF("pw should succeed when old bytes match");
	if (file_read_at(tpl, 4, check, 4) != 0)
		FAILF("reread after write");
	if (memcmp(check, newb, 4) != 0)
		FAILF("file not updated");

	/* now attempt again with the *original* old bytes: file has
	 * newb there now, so this mismatches and must be refused. */
	if (sim_pw(tpl, 4, oldb, newb, 4) != -2)
		FAILF("pw should refuse on old-byte mismatch");
	if (file_read_at(tpl, 4, check, 4) != 0)
		FAILF("reread after refuse");
	if (memcmp(check, newb, 4) != 0)
		FAILF("file must be unchanged after refuse");

	remove(tpl);
#endif
}

int
main(void)
{
	test_init();
	test_record_basic();
	test_record_too_large();
	test_overlap();
	test_state_transitions();
	test_va_to_file();
	test_resolve_file();
	test_file_write_match();

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_patch ok\n");
	return 0;
}
