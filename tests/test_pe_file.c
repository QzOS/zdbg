/*
 * test_pe_file.c - unit tests for zpe_file_rva_to_offset().
 *
 * The PE helper is portable C99 (no <windows.h>), so we test it
 * on every platform by writing a synthesized minimal PE32+ image
 * to a temp file and exercising the boundary rules:
 *   - in-bounds RVA inside .text -> success
 *   - in-bounds RVA inside .data -> success
 *   - RVA past SizeOfRawData but inside VirtualSize (BSS tail)
 *     -> refused
 *   - range spanning two sections -> refused
 *   - len == 0 -> refused
 *   - non-PE / bad path -> refused
 *   - PE32 (not PE32+) -> refused
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#if defined(_WIN32)
#include <windows.h>
#include <process.h>
#else
#include <unistd.h>
#endif

#include "zdbg_pe.h"

static int failures;

#define FAILF(...) do {                                               \
	fprintf(stderr, "FAIL %s:%d ", __FILE__, __LINE__);           \
	fprintf(stderr, __VA_ARGS__);                                 \
	fprintf(stderr, "\n");                                        \
	failures++;                                                   \
} while (0)

/* Little-endian writers. */
static void
wr16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v & 0xff);
	p[1] = (uint8_t)((v >> 8) & 0xff);
}

static void
wr32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v & 0xff);
	p[1] = (uint8_t)((v >> 8) & 0xff);
	p[2] = (uint8_t)((v >> 16) & 0xff);
	p[3] = (uint8_t)((v >> 24) & 0xff);
}

/*
 * Layout of the synthesized image:
 *   0x000  DOS header (64 bytes), e_lfanew = 0x40
 *   0x040  PE signature (4 bytes)
 *   0x044  IMAGE_FILE_HEADER (20 bytes)
 *   0x058  IMAGE_OPTIONAL_HEADER64 (240 bytes - we only fill
 *          the first 2 bytes Magic = 0x20b; the rest stays 0)
 *   0x148  Section table: 2 sections * 40 bytes
 *   0x200  Raw bytes for .text (size 0x100)
 *   0x300  Raw bytes for .data (raw 0x100, virtual 0x200)
 *
 * Section virtual addresses:
 *   .text  RVA 0x1000, VSize 0x100, RawSize 0x100
 *   .data  RVA 0x2000, VSize 0x200, RawSize 0x100
 *
 * That gives us:
 *   - .text in-bounds RVA range
 *   - .data RVAs 0x2000..0x20ff are file-backed; 0x2100..0x21ff
 *     are virtual-only (BSS-like) and must be refused.
 */
#define IMG_SIZE        0x400
#define DOS_HDR         64
#define E_LFANEW        0x40
#define FH_OFF          (E_LFANEW + 4)
#define OH_OFF          (FH_OFF + 20)
#define OH_SIZE         240
#define SEC_OFF         (OH_OFF + OH_SIZE)
#define TEXT_RAW_PTR    0x200
#define DATA_RAW_PTR    0x300

static void
build_pe64(uint8_t *img, int as_pe32)
{
	memset(img, 0, IMG_SIZE);

	/* DOS header */
	img[0] = 'M';
	img[1] = 'Z';
	wr32(img + 0x3c, E_LFANEW);

	/* PE signature */
	img[E_LFANEW + 0] = 'P';
	img[E_LFANEW + 1] = 'E';
	img[E_LFANEW + 2] = 0;
	img[E_LFANEW + 3] = 0;

	/* IMAGE_FILE_HEADER */
	wr16(img + FH_OFF + 0, 0x8664);   /* Machine = AMD64 */
	wr16(img + FH_OFF + 2, 2);        /* NumberOfSections */
	wr32(img + FH_OFF + 4, 0);
	wr32(img + FH_OFF + 8, 0);
	wr32(img + FH_OFF + 12, 0);
	wr16(img + FH_OFF + 16, OH_SIZE); /* SizeOfOptionalHeader */
	wr16(img + FH_OFF + 18, 0x22);    /* Characteristics */

	/* Optional header magic: PE32+ unless told otherwise. */
	wr16(img + OH_OFF + 0, as_pe32 ? 0x010b : 0x020b);

	/* Section .text */
	memcpy(img + SEC_OFF + 0, ".text\0\0\0", 8);
	wr32(img + SEC_OFF + 8, 0x100);   /* VirtualSize */
	wr32(img + SEC_OFF + 12, 0x1000); /* VirtualAddress */
	wr32(img + SEC_OFF + 16, 0x100);  /* SizeOfRawData */
	wr32(img + SEC_OFF + 20, TEXT_RAW_PTR);

	/* Section .data */
	memcpy(img + SEC_OFF + 40, ".data\0\0\0", 8);
	wr32(img + SEC_OFF + 40 + 8, 0x200);   /* VirtualSize > raw */
	wr32(img + SEC_OFF + 40 + 12, 0x2000); /* VirtualAddress */
	wr32(img + SEC_OFF + 40 + 16, 0x100);  /* SizeOfRawData */
	wr32(img + SEC_OFF + 40 + 20, DATA_RAW_PTR);

	/* Mark a recognizable byte at .text RVA 0x1010. */
	img[TEXT_RAW_PTR + 0x10] = 0xcc;
	img[DATA_RAW_PTR + 0x40] = 0xab;
}

static const char *
make_temp_path(char *buf, size_t cap, const char *tag)
{
#if defined(_WIN32)
	const char *tmp = getenv("TEMP");
	if (tmp == NULL || tmp[0] == 0)
		tmp = ".";
	snprintf(buf, cap, "%s\\zdbg_pe_%s_%lu.bin",
	    tmp, tag, (unsigned long)GetCurrentProcessId());
#else
	const char *tmp = getenv("TMPDIR");
	if (tmp == NULL || tmp[0] == 0)
		tmp = "/tmp";
	snprintf(buf, cap, "%s/zdbg_pe_%s_%lu.bin",
	    tmp, tag, (unsigned long)getpid());
#endif
	return buf;
}

static int
write_file(const char *path, const uint8_t *buf, size_t n)
{
	FILE *f = fopen(path, "wb");
	size_t w;
	if (f == NULL)
		return -1;
	w = fwrite(buf, 1, n, f);
	fclose(f);
	return w == n ? 0 : -1;
}

static void
test_pe64_basic(void)
{
	uint8_t img[IMG_SIZE];
	char path[512];
	uint64_t off;

	build_pe64(img, 0);
	make_temp_path(path, sizeof(path), "basic");
	if (write_file(path, img, sizeof(img)) < 0) {
		FAILF("write %s", path);
		return;
	}

	/* .text in-bounds. */
	off = 0;
	if (zpe_file_rva_to_offset(path, 0x1010, 4, &off) != 0)
		FAILF(".text RVA 0x1010 should resolve");
	else if (off != TEXT_RAW_PTR + 0x10)
		FAILF(".text off 0x%llx", (unsigned long long)off);

	/* .text exact end is OK. */
	off = 0;
	if (zpe_file_rva_to_offset(path, 0x10ff, 1, &off) != 0)
		FAILF(".text last byte should resolve");
	else if (off != TEXT_RAW_PTR + 0xff)
		FAILF(".text tail off 0x%llx", (unsigned long long)off);

	/* .text past raw end -> refuse. */
	if (zpe_file_rva_to_offset(path, 0x1100, 1, &off) == 0)
		FAILF("RVA past .text raw should refuse");

	/* .data in raw range -> ok. */
	off = 0;
	if (zpe_file_rva_to_offset(path, 0x2040, 4, &off) != 0)
		FAILF(".data RVA 0x2040 should resolve");
	else if (off != DATA_RAW_PTR + 0x40)
		FAILF(".data off 0x%llx", (unsigned long long)off);

	/* .data RVA past SizeOfRawData but inside VirtualSize -> refuse */
	if (zpe_file_rva_to_offset(path, 0x2100, 4, &off) == 0)
		FAILF("BSS tail RVA must be refused");

	/* range straddling section raw end -> refuse */
	if (zpe_file_rva_to_offset(path, 0x10fe, 4, &off) == 0)
		FAILF("range spanning .text raw end must be refused");

	/* range spanning .text and .data RVAs -> refuse */
	if (zpe_file_rva_to_offset(path, 0x10fc, 0x1010, &off) == 0)
		FAILF("range spanning two sections must be refused");

	/* len == 0 -> refuse */
	if (zpe_file_rva_to_offset(path, 0x1010, 0, &off) == 0)
		FAILF("len=0 must be refused");

	remove(path);
}

static void
test_pe32_refused(void)
{
	uint8_t img[IMG_SIZE];
	char path[512];
	uint64_t off = 0;

	build_pe64(img, 1);	/* PE32 magic */
	make_temp_path(path, sizeof(path), "pe32");
	if (write_file(path, img, sizeof(img)) < 0) {
		FAILF("write %s", path);
		return;
	}
	if (zpe_file_rva_to_offset(path, 0x1010, 4, &off) == 0)
		FAILF("PE32 should be refused");
	remove(path);
}

static void
test_bad_inputs(void)
{
	uint64_t off = 0;
	uint8_t junk[64];
	char path[512];

	/* NULL / empty path */
	if (zpe_file_rva_to_offset(NULL, 0, 4, &off) == 0)
		FAILF("NULL path should fail");
	if (zpe_file_rva_to_offset("", 0, 4, &off) == 0)
		FAILF("empty path should fail");

	/* nonexistent path */
	if (zpe_file_rva_to_offset(
	    "/this/path/should/not/exist/zdbg_pe_xxx", 0, 4, &off) == 0)
		FAILF("nonexistent path should fail");

	/* file too small / not a PE */
	memset(junk, 0, sizeof(junk));
	make_temp_path(path, sizeof(path), "junk");
	if (write_file(path, junk, sizeof(junk)) < 0) {
		FAILF("write %s", path);
		return;
	}
	if (zpe_file_rva_to_offset(path, 0, 4, &off) == 0)
		FAILF("non-PE file should be refused");
	remove(path);
}

int
main(void)
{
	test_pe64_basic();
	test_pe32_refused();
	test_bad_inputs();

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_pe_file ok\n");
	return 0;
}
