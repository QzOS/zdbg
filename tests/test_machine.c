/*
 * test_machine.c - tests for the executable machine detector.
 *
 * Builds tiny on-disk ELF/PE header fixtures in temporary
 * files and checks zmachine_detect_file() classifies them
 * correctly.  Only headers are written; the resulting files
 * are not loadable executables, but the detector only reads
 * header bytes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zdbg_machine.h"
#include "zdbg_target.h"
#include "zdbg_regfile.h"

static int failures;

#define EXPECT_EQ(got, want) do {                                   \
	long long _g = (long long)(got);                            \
	long long _w = (long long)(want);                           \
	if (_g != _w) {                                             \
		fprintf(stderr,                                     \
		    "FAIL %s:%d expected %lld, got %lld\n",         \
		    __FILE__, __LINE__, _w, _g);                    \
		failures++;                                         \
	}                                                           \
} while (0)

#define EXPECT_TRUE(cond) do {                                      \
	if (!(cond)) {                                              \
		fprintf(stderr,                                     \
		    "FAIL %s:%d expected true: %s\n",               \
		    __FILE__, __LINE__, #cond);                     \
		failures++;                                         \
	}                                                           \
} while (0)

static void
write_file(const char *path, const unsigned char *buf, size_t len)
{
	FILE *fp = fopen(path, "wb");
	if (fp == NULL) {
		fprintf(stderr, "could not open %s for write\n", path);
		exit(1);
	}
	fwrite(buf, 1, len, fp);
	fclose(fp);
}

/* Build a minimal little-endian ELF64 header buffer with the
 * given e_machine value. */
static size_t
build_elf64(unsigned char *buf, unsigned char ei_class,
    unsigned char ei_data, uint16_t emach)
{
	size_t off;

	memset(buf, 0, 64);
	buf[0] = 0x7f;
	buf[1] = 'E';
	buf[2] = 'L';
	buf[3] = 'F';
	buf[4] = ei_class;
	buf[5] = ei_data;
	buf[6] = 1; /* EI_VERSION */
	/* e_type at 0x10 = 2 (EXEC); e_machine at 0x12 (LE). */
	buf[0x10] = 2;
	buf[0x11] = 0;
	off = 0x12;
	buf[off] = (unsigned char)(emach & 0xff);
	buf[off + 1] = (unsigned char)((emach >> 8) & 0xff);
	return 64;
}

/* Build a minimal MZ + PE/COFF header layout placing the PE
 * signature at offset 0x80.  Optional header magic at offset
 * (0x80 + 24) selects PE32 vs PE32+. */
static size_t
build_pe(unsigned char *buf, uint16_t machine, uint16_t opt_magic)
{
	size_t pe_off = 0x80;

	memset(buf, 0, 0x100);
	buf[0] = 'M';
	buf[1] = 'Z';
	/* e_lfanew at 0x3c = 0x80 (LE). */
	buf[0x3c] = 0x80;
	buf[0x3d] = 0x00;
	buf[0x3e] = 0x00;
	buf[0x3f] = 0x00;
	/* "PE\0\0" at pe_off */
	buf[pe_off + 0] = 'P';
	buf[pe_off + 1] = 'E';
	buf[pe_off + 2] = 0;
	buf[pe_off + 3] = 0;
	/* IMAGE_FILE_HEADER follows: Machine[2], NumberOfSections[2],
	 * TimeDateStamp[4], PointerToSymbolTable[4],
	 * NumberOfSymbols[4], SizeOfOptionalHeader[2],
	 * Characteristics[2].  Only Machine and SizeOfOptionalHeader
	 * matter for detection. */
	buf[pe_off + 4] = (unsigned char)(machine & 0xff);
	buf[pe_off + 5] = (unsigned char)((machine >> 8) & 0xff);
	/* SizeOfOptionalHeader = 0xf0 (any nonzero value works). */
	buf[pe_off + 4 + 16] = 0xf0;
	buf[pe_off + 4 + 17] = 0x00;
	/* Optional header magic at pe_off + 24 */
	buf[pe_off + 24] = (unsigned char)(opt_magic & 0xff);
	buf[pe_off + 25] = (unsigned char)((opt_magic >> 8) & 0xff);
	return 0x100;
}

static void
test_elf64_x86_64(void)
{
	unsigned char buf[256];
	enum zarch a = ZARCH_NONE;
	char err[128];
	size_t n = build_elf64(buf, 2, 1, 62);
	const char *p = "/tmp/zdbg_test_elf_x86_64";

	write_file(p, buf, n);
	EXPECT_EQ(zmachine_detect_file(p, &a, err, sizeof(err)), 0);
	EXPECT_EQ((int)a, (int)ZARCH_X86_64);
	remove(p);
}

static void
test_elf64_aarch64(void)
{
	unsigned char buf[256];
	enum zarch a = ZARCH_NONE;
	char err[128];
	size_t n = build_elf64(buf, 2, 1, 183);
	const char *p = "/tmp/zdbg_test_elf_aarch64";

	write_file(p, buf, n);
	EXPECT_EQ(zmachine_detect_file(p, &a, err, sizeof(err)), 0);
	EXPECT_EQ((int)a, (int)ZARCH_AARCH64);
	remove(p);
}

static void
test_elf32_unsupported(void)
{
	unsigned char buf[256];
	enum zarch a = ZARCH_NONE;
	char err[128];
	size_t n = build_elf64(buf, 1, 1, 3 /* EM_386 */);
	const char *p = "/tmp/zdbg_test_elf32";

	write_file(p, buf, n);
	EXPECT_EQ(zmachine_detect_file(p, &a, err, sizeof(err)), -2);
	EXPECT_TRUE(strstr(err, "32-bit") != NULL);
	remove(p);
}

static void
test_elf64_unknown(void)
{
	unsigned char buf[256];
	enum zarch a = ZARCH_NONE;
	char err[128];
	/* EM_PPC = 20, not recognized by zdbg. */
	size_t n = build_elf64(buf, 2, 1, 20);
	const char *p = "/tmp/zdbg_test_elf_ppc";

	write_file(p, buf, n);
	EXPECT_EQ(zmachine_detect_file(p, &a, err, sizeof(err)), -2);
	EXPECT_TRUE(strstr(err, "unsupported") != NULL);
	remove(p);
}

static void
test_pe_amd64(void)
{
	unsigned char buf[512];
	enum zarch a = ZARCH_NONE;
	char err[128];
	size_t n = build_pe(buf, 0x8664, 0x20b);
	const char *p = "/tmp/zdbg_test_pe_amd64";

	write_file(p, buf, n);
	EXPECT_EQ(zmachine_detect_file(p, &a, err, sizeof(err)), 0);
	EXPECT_EQ((int)a, (int)ZARCH_X86_64);
	remove(p);
}

static void
test_pe_arm64(void)
{
	unsigned char buf[512];
	enum zarch a = ZARCH_NONE;
	char err[128];
	size_t n = build_pe(buf, 0xaa64, 0x20b);
	const char *p = "/tmp/zdbg_test_pe_arm64";

	write_file(p, buf, n);
	EXPECT_EQ(zmachine_detect_file(p, &a, err, sizeof(err)), 0);
	EXPECT_EQ((int)a, (int)ZARCH_AARCH64);
	remove(p);
}

static void
test_pe32_unsupported(void)
{
	unsigned char buf[512];
	enum zarch a = ZARCH_NONE;
	char err[128];
	size_t n = build_pe(buf, 0x014c, 0x10b);
	const char *p = "/tmp/zdbg_test_pe32";

	write_file(p, buf, n);
	EXPECT_EQ(zmachine_detect_file(p, &a, err, sizeof(err)), -2);
	EXPECT_TRUE(strstr(err, "32-bit") != NULL ||
	    strstr(err, "PE32") != NULL);
	remove(p);
}

static void
test_random_bytes(void)
{
	unsigned char buf[16] = { 'X', 'Y', 'Z', 0, 1, 2, 3, 4 };
	enum zarch a = ZARCH_NONE;
	char err[128];
	const char *p = "/tmp/zdbg_test_random";

	write_file(p, buf, sizeof(buf));
	EXPECT_EQ(zmachine_detect_file(p, &a, err, sizeof(err)), -1);
	EXPECT_TRUE(err[0] != 0);
	remove(p);
}

static void
test_missing_file(void)
{
	enum zarch a = ZARCH_NONE;
	char err[128];

	EXPECT_EQ(zmachine_detect_file(
	    "/tmp/zdbg_test_definitely_missing_xyz",
	    &a, err, sizeof(err)), -1);
	EXPECT_TRUE(err[0] != 0);
}

/* --- target regfile API basics -------------------------------- */

static void
test_target_regfile_null(void)
{
	struct ztarget t;
	struct zreg_file rf;

	ztarget_init(&t);
	zregfile_init(&rf, ZARCH_X86_64);
	/* Without an active backend launch the get path must
	 * fail cleanly. */
	EXPECT_EQ(ztarget_get_regfile(&t, ZARCH_X86_64, &rf), -1);
	EXPECT_EQ(ztarget_set_regfile(&t, ZARCH_X86_64, &rf), -1);
	/* Unsupported arch must fail cleanly even if a backend
	 * were attached. */
	EXPECT_EQ(ztarget_get_regfile(&t, ZARCH_AARCH64, &rf), -1);
	EXPECT_EQ(ztarget_set_regfile(&t, ZARCH_AARCH64, &rf), -1);
	ztarget_fini(&t);
}

int
main(void)
{
	test_elf64_x86_64();
	test_elf64_aarch64();
	test_elf32_unsupported();
	test_elf64_unknown();
	test_pe_amd64();
	test_pe_arm64();
	test_pe32_unsupported();
	test_random_bytes();
	test_missing_file();
	test_target_regfile_null();
	if (failures != 0) {
		fprintf(stderr, "test_machine: %d failure(s)\n",
		    failures);
		return 1;
	}
	printf("test_machine: ok\n");
	return 0;
}
