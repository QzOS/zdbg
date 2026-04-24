/*
 * test_tinyasm.c - tests for the tiny patch encoder.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_tinyasm.h"

static int failures;

static void
fail(const char *msg, int line)
{
	fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, line, msg);
	failures++;
}

#define MUST_EQ(a, b) do { if ((a) != (b)) fail(#a " != " #b, __LINE__); } while (0)

static int
bytes_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
	return memcmp(a, b, n) == 0;
}

static void
test_fixed(void)
{
	struct ztinyasm enc;

	MUST_EQ(ztinyasm_assemble(0x400000, "nop", &enc, NULL), 0);
	MUST_EQ(enc.len, 1);
	MUST_EQ(enc.code[0], 0x90);

	MUST_EQ(ztinyasm_assemble(0x400000, "int3", &enc, NULL), 0);
	MUST_EQ(enc.len, 1);
	MUST_EQ(enc.code[0], 0xcc);

	MUST_EQ(ztinyasm_assemble(0x400000, "ret", &enc, NULL), 0);
	MUST_EQ(enc.len, 1);
	MUST_EQ(enc.code[0], 0xc3);

	/* case-insensitive */
	MUST_EQ(ztinyasm_assemble(0x400000, "NOP", &enc, NULL), 0);
	MUST_EQ(enc.code[0], 0x90);
}

static void
test_jmp_rel32(void)
{
	struct ztinyasm enc;
	uint8_t want[5];

	/* jmp 0x401080 from 0x401000 -> e9 7b 00 00 00 */
	MUST_EQ(ztinyasm_assemble(0x401000, "jmp 0x401080", &enc, NULL), 0);
	MUST_EQ(enc.len, 5);
	want[0] = 0xe9; want[1] = 0x7b; want[2] = 0; want[3] = 0; want[4] = 0;
	if (!bytes_eq(enc.code, want, 5)) fail("jmp rel32 forward", __LINE__);

	/* jmp backward */
	MUST_EQ(ztinyasm_assemble(0x401000, "jmp 0x400000", &enc, NULL), 0);
	MUST_EQ(enc.len, 5);
	/* rel = 0x400000 - 0x401005 = -0x1005 = 0xffffefffb */
	want[0] = 0xe9;
	want[1] = 0xfb;
	want[2] = 0xef;
	want[3] = 0xff;
	want[4] = 0xff;
	if (!bytes_eq(enc.code, want, 5)) fail("jmp rel32 backward", __LINE__);
}

static void
test_jmp_rel8(void)
{
	struct ztinyasm enc;

	MUST_EQ(ztinyasm_assemble(0x401000, "jmp8 0x401010", &enc, NULL), 0);
	MUST_EQ(enc.len, 2);
	MUST_EQ(enc.code[0], 0xeb);
	MUST_EQ(enc.code[1], 0x0e);

	MUST_EQ(ztinyasm_assemble(0x401000, "jmp8 0x400ff0", &enc, NULL), 0);
	MUST_EQ(enc.len, 2);
	MUST_EQ(enc.code[0], 0xeb);
	MUST_EQ(enc.code[1], 0xee);

	/* out of rel8 range -> fail */
	MUST_EQ(ztinyasm_assemble(0x401000, "jmp8 0x401100", &enc, NULL), -1);
}

static void
test_jcc(void)
{
	struct ztinyasm enc;
	uint8_t want[6];

	/* jz rel32 */
	MUST_EQ(ztinyasm_assemble(0x401000, "jz 0x401080", &enc, NULL), 0);
	MUST_EQ(enc.len, 6);
	want[0] = 0x0f; want[1] = 0x84;
	want[2] = 0x7a; want[3] = 0; want[4] = 0; want[5] = 0;
	if (!bytes_eq(enc.code, want, 6)) fail("jz rel32", __LINE__);

	/* jnz rel32 */
	MUST_EQ(ztinyasm_assemble(0x401000, "jnz 0x401080", &enc, NULL), 0);
	MUST_EQ(enc.len, 6);
	want[1] = 0x85;
	if (!bytes_eq(enc.code, want, 6)) fail("jnz rel32", __LINE__);

	/* je alias */
	MUST_EQ(ztinyasm_assemble(0x401000, "je 0x401080", &enc, NULL), 0);
	MUST_EQ(enc.code[1], 0x84);

	/* jz8 */
	MUST_EQ(ztinyasm_assemble(0x401000, "jz8 0x401010", &enc, NULL), 0);
	MUST_EQ(enc.len, 2);
	MUST_EQ(enc.code[0], 0x74);
	MUST_EQ(enc.code[1], 0x0e);

	/* jnz8 */
	MUST_EQ(ztinyasm_assemble(0x401000, "jnz8 0x401010", &enc, NULL), 0);
	MUST_EQ(enc.code[0], 0x75);
}

static void
test_patch(void)
{
	uint8_t buf[16];
	size_t len = 0;
	uint8_t want[6];

	MUST_EQ(ztinyasm_patch(0x401000, 6, "jmp 0x401080", buf, sizeof(buf),
	    &len, NULL), 0);
	MUST_EQ(len, 6);
	want[0] = 0xe9; want[1] = 0x7b; want[2] = 0; want[3] = 0; want[4] = 0;
	want[5] = 0x90;
	if (!bytes_eq(buf, want, 6)) fail("patch nop fill", __LINE__);

	/* patch_len smaller than encoding -> fail */
	MUST_EQ(ztinyasm_patch(0x401000, 4, "jmp 0x401080", buf, sizeof(buf),
	    &len, NULL), -1);
}

static void
test_rel32_range(void)
{
	/*
	 * jmp rel32 with a target more than 2GiB away should fail.
	 * 0x0 -> 0xffffffff80000001 exceeds int32 range.
	 */
	struct ztinyasm enc;
	MUST_EQ(ztinyasm_assemble(0x0, "jmp 0xffffffff80000000", &enc, NULL),
	    -1);
}

static void
test_invert_jcc(void)
{
	uint8_t b[6];
	size_t used = 0;

	b[0] = 0x74; b[1] = 0x10;
	MUST_EQ(zpatch_invert_jcc(b, 2, &used), 0);
	MUST_EQ(b[0], 0x75);
	MUST_EQ(used, 2);

	b[0] = 0x75; b[1] = 0x10;
	MUST_EQ(zpatch_invert_jcc(b, 2, &used), 0);
	MUST_EQ(b[0], 0x74);

	b[0] = 0x0f; b[1] = 0x84; b[2] = 0; b[3] = 0; b[4] = 0; b[5] = 0;
	MUST_EQ(zpatch_invert_jcc(b, 6, &used), 0);
	MUST_EQ(b[1], 0x85);
	MUST_EQ(used, 6);

	b[0] = 0x0f; b[1] = 0x85;
	MUST_EQ(zpatch_invert_jcc(b, 6, &used), 0);
	MUST_EQ(b[1], 0x84);

	/* not a recognised jcc */
	b[0] = 0x90;
	MUST_EQ(zpatch_invert_jcc(b, 2, &used), -1);
}

int
main(void)
{
	test_fixed();
	test_jmp_rel32();
	test_jmp_rel8();
	test_jcc();
	test_patch();
	test_rel32_range();
	test_invert_jcc();

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_tinyasm ok\n");
	return 0;
}
