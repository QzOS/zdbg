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

/*
 * Fake resolver used by the symbol-aware tests.  Mimics what
 * the command layer plugs in but without any live target.
 */
static int last_resolve_calls;
static char last_resolve_expr[128];

static int
fake_resolve(void *arg, const char *expr, zaddr_t *out)
{
	(void)arg;
	last_resolve_calls++;
	snprintf(last_resolve_expr, sizeof(last_resolve_expr), "%s",
	    expr);
	if (strcmp(expr, "foo") == 0) {
		*out = 0x401000;
		return 0;
	}
	if (strcmp(expr, "main + 20") == 0) {
		*out = 0x402000;
		return 0;
	}
	if (strcmp(expr, "ptr ( rsp )") == 0) {
		*out = 0x403000;
		return 0;
	}
	if (strcmp(expr, "kernel32:GetCurrentProcess") == 0) {
		*out = 0x7fff00000000ULL;
		return 0;
	}
	if (strcmp(expr, "near") == 0) {
		*out = 0x400005;
		return 0;
	}
	/* numeric fallback for hex literals */
	if (expr[0] == '0' && (expr[1] == 'x' || expr[1] == 'X')) {
		unsigned long long v = 0;
		if (sscanf(expr, "%llx", &v) == 1) {
			*out = (zaddr_t)v;
			return 0;
		}
	}
	return -1;
}

static void
test_call_rel32(void)
{
	struct ztinyasm enc;
	uint8_t want[5];

	/* call 0x401005 from 0x401000 -> e8 00 00 00 00 */
	MUST_EQ(ztinyasm_assemble(0x401000, "call 0x401005", &enc, NULL), 0);
	MUST_EQ(enc.len, 5);
	want[0] = 0xe8; want[1] = 0; want[2] = 0; want[3] = 0; want[4] = 0;
	if (!bytes_eq(enc.code, want, 5)) fail("call rel32 zero", __LINE__);

	/* call backward */
	MUST_EQ(ztinyasm_assemble(0x401000, "call 0x400000", &enc, NULL), 0);
	MUST_EQ(enc.len, 5);
	want[0] = 0xe8;
	want[1] = 0xfb;
	want[2] = 0xef;
	want[3] = 0xff;
	want[4] = 0xff;
	if (!bytes_eq(enc.code, want, 5)) fail("call rel32 back", __LINE__);

	/* out of rel32 range */
	MUST_EQ(ztinyasm_assemble(0x0, "call 0xffffffff80000000", &enc,
	    NULL), -1);
}

static void
test_resolver_callback(void)
{
	struct ztinyasm enc;
	char err[128];
	uint8_t want[5];

	last_resolve_calls = 0;
	last_resolve_expr[0] = 0;

	/* jmp foo -> resolver invoked, encodes E9 rel32 */
	MUST_EQ(ztinyasm_assemble_ex(0x400000, "jmp foo", &enc,
	    fake_resolve, NULL, err, sizeof(err)), 0);
	MUST_EQ(enc.len, 5);
	if (last_resolve_calls != 1) fail("resolver not called", __LINE__);
	if (strcmp(last_resolve_expr, "foo") != 0)
		fail("resolver expr mismatch", __LINE__);
	{
		int64_t rel = (int64_t)0x401000 - (int64_t)(0x400000 + 5);
		want[0] = 0xe9;
		want[1] = (uint8_t)(rel & 0xff);
		want[2] = (uint8_t)((rel >> 8) & 0xff);
		want[3] = (uint8_t)((rel >> 16) & 0xff);
		want[4] = (uint8_t)((rel >> 24) & 0xff);
		if (!bytes_eq(enc.code, want, 5))
			fail("jmp foo encoding", __LINE__);
	}

	/* call symbol via callback */
	MUST_EQ(ztinyasm_assemble_ex(0x400000, "call foo", &enc,
	    fake_resolve, NULL, err, sizeof(err)), 0);
	MUST_EQ(enc.len, 5);
	MUST_EQ(enc.code[0], 0xe8);

	/* jz symbol via callback (near form, 6 bytes) */
	MUST_EQ(ztinyasm_assemble_ex(0x400000, "jz foo", &enc,
	    fake_resolve, NULL, err, sizeof(err)), 0);
	MUST_EQ(enc.len, 6);
	MUST_EQ(enc.code[0], 0x0f);
	MUST_EQ(enc.code[1], 0x84);
}

static void
test_resolver_spaces(void)
{
	struct ztinyasm enc;
	char err[128];

	/* operand "main + 20" must be passed whole, including spaces */
	last_resolve_expr[0] = 0;
	MUST_EQ(ztinyasm_assemble_ex(0x400000, "call main + 20", &enc,
	    fake_resolve, NULL, err, sizeof(err)), 0);
	MUST_EQ(enc.len, 5);
	if (strcmp(last_resolve_expr, "main + 20") != 0)
		fail("operand not preserved", __LINE__);

	/* explicit dereference form, with whitespace */
	last_resolve_expr[0] = 0;
	MUST_EQ(ztinyasm_assemble_ex(0x400000, "jmp ptr ( rsp )", &enc,
	    fake_resolve, NULL, err, sizeof(err)), 0);
	if (strcmp(last_resolve_expr, "ptr ( rsp )") != 0)
		fail("dereference operand not preserved", __LINE__);

	/* trailing whitespace must be trimmed but interior preserved */
	last_resolve_expr[0] = 0;
	MUST_EQ(ztinyasm_assemble_ex(0x400000,
	    "call    kernel32:GetCurrentProcess   ", &enc,
	    fake_resolve, NULL, err, sizeof(err)), -1);
	if (strcmp(last_resolve_expr,
	    "kernel32:GetCurrentProcess") != 0)
		fail("module:symbol operand not preserved", __LINE__);
	/* far DLL out of rel32 range -> honest error */
	if (strstr(err, "rel32") == NULL)
		fail("expected rel32 range error", __LINE__);
}

static void
test_resolver_failure(void)
{
	struct ztinyasm enc;
	char err[128];

	/* unknown symbol -> resolver returns -1 -> assemble fails */
	MUST_EQ(ztinyasm_assemble_ex(0x400000, "jmp nope", &enc,
	    fake_resolve, NULL, err, sizeof(err)), -1);
	if (strstr(err, "bad target expression") == NULL)
		fail("expected bad target err", __LINE__);

	/* missing operand */
	MUST_EQ(ztinyasm_assemble_ex(0x400000, "jmp", &enc,
	    fake_resolve, NULL, err, sizeof(err)), -1);
	if (strstr(err, "missing operand") == NULL)
		fail("expected missing operand err", __LINE__);

	/* unknown mnemonic */
	MUST_EQ(ztinyasm_assemble_ex(0x400000, "blarg foo", &enc,
	    fake_resolve, NULL, err, sizeof(err)), -1);
	if (strstr(err, "unknown instruction") == NULL)
		fail("expected unknown instruction err", __LINE__);
}

static void
test_no_operand_garbage(void)
{
	struct ztinyasm enc;
	char err[128];

	MUST_EQ(ztinyasm_assemble_ex(0x400000, "ret", &enc,
	    fake_resolve, NULL, err, sizeof(err)), 0);
	MUST_EQ(enc.len, 1);
	MUST_EQ(enc.code[0], 0xc3);

	/* ret with trailing junk -> error */
	MUST_EQ(ztinyasm_assemble_ex(0x400000, "ret garbage", &enc,
	    fake_resolve, NULL, err, sizeof(err)), -1);
	if (strstr(err, "no operand") == NULL)
		fail("expected no operand err", __LINE__);

	/* trailing whitespace alone is fine */
	MUST_EQ(ztinyasm_assemble_ex(0x400000, "nop   ", &enc,
	    fake_resolve, NULL, err, sizeof(err)), 0);
	MUST_EQ(enc.len, 1);
	MUST_EQ(enc.code[0], 0x90);
}

static void
test_jz_jnz_8_range(void)
{
	struct ztinyasm enc;

	/* jz8 out of range */
	MUST_EQ(ztinyasm_assemble(0x401000, "jz8 0x401100", &enc, NULL), -1);
	/* jnz8 out of range */
	MUST_EQ(ztinyasm_assemble(0x401000, "jnz8 0x401100", &enc, NULL), -1);
}

/*
 * Build the expected `49 BB <imm64-le> 41 FF <op>` tail byte pattern
 * into `want` starting at offset `off`.  `last` is 0xE3 for jmp r11
 * or 0xD3 for call r11.
 */
static void
build_movabs_tail(uint8_t *want, size_t off, uint64_t imm, uint8_t last)
{
	int i;
	want[off + 0] = 0x49;
	want[off + 1] = 0xbb;
	for (i = 0; i < 8; i++)
		want[off + 2 + i] = (uint8_t)((imm >> (i * 8)) & 0xff);
	want[off + 10] = 0x41;
	want[off + 11] = 0xff;
	want[off + 12] = last;
}

static void
test_jmpabs(void)
{
	struct ztinyasm enc;
	char err[128];
	uint8_t want[16];

	last_resolve_calls = 0;
	last_resolve_expr[0] = 0;
	MUST_EQ(ztinyasm_assemble_ex(0x400000,
	    "jmpabs kernel32:GetCurrentProcess", &enc,
	    fake_resolve, NULL, err, sizeof(err)), 0);
	MUST_EQ(enc.len, 13);
	if (last_resolve_calls != 1)
		fail("jmpabs: resolver not called once", __LINE__);
	if (strcmp(last_resolve_expr,
	    "kernel32:GetCurrentProcess") != 0)
		fail("jmpabs: operand not preserved", __LINE__);
	build_movabs_tail(want, 0, 0x7fff00000000ULL, 0xe3);
	if (!bytes_eq(enc.code, want, 13))
		fail("jmpabs encoding", __LINE__);

	/* Address-independent: same bytes regardless of `addr`. */
	MUST_EQ(ztinyasm_assemble_ex(0xdeadbeefULL,
	    "jmpabs kernel32:GetCurrentProcess", &enc,
	    fake_resolve, NULL, err, sizeof(err)), 0);
	if (!bytes_eq(enc.code, want, 13))
		fail("jmpabs not address-independent", __LINE__);
}

static void
test_callabs(void)
{
	struct ztinyasm enc;
	char err[128];
	uint8_t want[16];

	MUST_EQ(ztinyasm_assemble_ex(0x400000, "callabs foo", &enc,
	    fake_resolve, NULL, err, sizeof(err)), 0);
	MUST_EQ(enc.len, 13);
	build_movabs_tail(want, 0, 0x401000ULL, 0xd3);
	if (!bytes_eq(enc.code, want, 13))
		fail("callabs encoding", __LINE__);
}

static void
test_jzabs(void)
{
	struct ztinyasm enc;
	char err[128];
	uint8_t want[16];

	/* jzabs foo: 75 0D | movabs r11, 0x401000 | jmp r11 */
	MUST_EQ(ztinyasm_assemble_ex(0x400000, "jzabs foo", &enc,
	    fake_resolve, NULL, err, sizeof(err)), 0);
	MUST_EQ(enc.len, 15);
	want[0] = 0x75; want[1] = 0x0d;
	build_movabs_tail(want, 2, 0x401000ULL, 0xe3);
	if (!bytes_eq(enc.code, want, 15))
		fail("jzabs encoding", __LINE__);

	/* jeabs is an alias for jzabs */
	MUST_EQ(ztinyasm_assemble_ex(0x400000, "jeabs foo", &enc,
	    fake_resolve, NULL, err, sizeof(err)), 0);
	MUST_EQ(enc.len, 15);
	if (!bytes_eq(enc.code, want, 15))
		fail("jeabs encoding (alias of jzabs)", __LINE__);
}

static void
test_jnzabs(void)
{
	struct ztinyasm enc;
	char err[128];
	uint8_t want[16];

	/* jnzabs foo: 74 0D | movabs r11, 0x401000 | jmp r11 */
	MUST_EQ(ztinyasm_assemble_ex(0x400000, "jnzabs foo", &enc,
	    fake_resolve, NULL, err, sizeof(err)), 0);
	MUST_EQ(enc.len, 15);
	want[0] = 0x74; want[1] = 0x0d;
	build_movabs_tail(want, 2, 0x401000ULL, 0xe3);
	if (!bytes_eq(enc.code, want, 15))
		fail("jnzabs encoding", __LINE__);

	/* jneabs is an alias for jnzabs */
	MUST_EQ(ztinyasm_assemble_ex(0x400000, "jneabs foo", &enc,
	    fake_resolve, NULL, err, sizeof(err)), 0);
	MUST_EQ(enc.len, 15);
	if (!bytes_eq(enc.code, want, 15))
		fail("jneabs encoding (alias of jnzabs)", __LINE__);
}

static void
test_abs_resolver_failure(void)
{
	struct ztinyasm enc;
	char err[128];

	/* Bad target expression -> bad target err for every abs form. */
	err[0] = 0;
	MUST_EQ(ztinyasm_assemble_ex(0x400000, "jmpabs nope", &enc,
	    fake_resolve, NULL, err, sizeof(err)), -1);
	if (strstr(err, "bad target expression") == NULL)
		fail("jmpabs: expected bad target err", __LINE__);

	err[0] = 0;
	MUST_EQ(ztinyasm_assemble_ex(0x400000, "callabs nope", &enc,
	    fake_resolve, NULL, err, sizeof(err)), -1);
	if (strstr(err, "bad target expression") == NULL)
		fail("callabs: expected bad target err", __LINE__);

	err[0] = 0;
	MUST_EQ(ztinyasm_assemble_ex(0x400000, "jzabs nope", &enc,
	    fake_resolve, NULL, err, sizeof(err)), -1);
	if (strstr(err, "bad target expression") == NULL)
		fail("jzabs: expected bad target err", __LINE__);

	/* Missing operand */
	err[0] = 0;
	MUST_EQ(ztinyasm_assemble_ex(0x400000, "jmpabs", &enc,
	    fake_resolve, NULL, err, sizeof(err)), -1);
	if (strstr(err, "missing operand") == NULL)
		fail("jmpabs: expected missing operand err", __LINE__);
}

static void
test_abs_multitoken_operand(void)
{
	struct ztinyasm enc;
	char err[128];

	/* Multi-token operand: spaces preserved. */
	last_resolve_expr[0] = 0;
	MUST_EQ(ztinyasm_assemble_ex(0x400000, "jmpabs main + 20", &enc,
	    fake_resolve, NULL, err, sizeof(err)), 0);
	MUST_EQ(enc.len, 13);
	if (strcmp(last_resolve_expr, "main + 20") != 0)
		fail("jmpabs: multi-token operand not preserved", __LINE__);
}

static void
test_abs_patch_length(void)
{
	uint8_t buf[16];
	size_t out_len = 0;
	char err[128];

	/* jmpabs needs 13 bytes: 12-byte patch must be rejected. */
	err[0] = 0;
	MUST_EQ(ztinyasm_patch_ex(0x401000, 12, "jmpabs foo", buf,
	    sizeof(buf), &out_len, fake_resolve, NULL,
	    err, sizeof(err)), -1);
	if (strstr(err, "exceeds patch length") == NULL)
		fail("jmpabs 12: expected length err", __LINE__);

	/* callabs likewise. */
	err[0] = 0;
	MUST_EQ(ztinyasm_patch_ex(0x401000, 12, "callabs foo", buf,
	    sizeof(buf), &out_len, fake_resolve, NULL,
	    err, sizeof(err)), -1);
	if (strstr(err, "exceeds patch length") == NULL)
		fail("callabs 12: expected length err", __LINE__);

	/* jzabs/jnzabs need 15 bytes: 14-byte patch must be rejected. */
	err[0] = 0;
	MUST_EQ(ztinyasm_patch_ex(0x401000, 14, "jzabs foo", buf,
	    sizeof(buf), &out_len, fake_resolve, NULL,
	    err, sizeof(err)), -1);
	if (strstr(err, "exceeds patch length") == NULL)
		fail("jzabs 14: expected length err", __LINE__);

	err[0] = 0;
	MUST_EQ(ztinyasm_patch_ex(0x401000, 14, "jnzabs foo", buf,
	    sizeof(buf), &out_len, fake_resolve, NULL,
	    err, sizeof(err)), -1);
	if (strstr(err, "exceeds patch length") == NULL)
		fail("jnzabs 14: expected length err", __LINE__);

	/* Exact-fit and NOP-fill: 13-byte jmpabs in a 13-byte patch
	 * succeeds; 14-byte patch succeeds and pads with one NOP. */
	err[0] = 0;
	MUST_EQ(ztinyasm_patch_ex(0x401000, 13, "jmpabs foo", buf,
	    sizeof(buf), &out_len, fake_resolve, NULL,
	    err, sizeof(err)), 0);
	MUST_EQ(out_len, 13);
	MUST_EQ(buf[0], 0x49);
	MUST_EQ(buf[1], 0xbb);
	MUST_EQ(buf[10], 0x41);
	MUST_EQ(buf[11], 0xff);
	MUST_EQ(buf[12], 0xe3);

	err[0] = 0;
	MUST_EQ(ztinyasm_patch_ex(0x401000, 14, "jmpabs foo", buf,
	    sizeof(buf), &out_len, fake_resolve, NULL,
	    err, sizeof(err)), 0);
	MUST_EQ(out_len, 14);
	MUST_EQ(buf[13], 0x90);  /* NOP fill */

	/* 15-byte jzabs in a 16-byte patch -> NOP-pads to 16. */
	err[0] = 0;
	MUST_EQ(ztinyasm_patch_ex(0x401000, 16, "jzabs foo", buf,
	    sizeof(buf), &out_len, fake_resolve, NULL,
	    err, sizeof(err)), 0);
	MUST_EQ(out_len, 16);
	MUST_EQ(buf[0], 0x75);
	MUST_EQ(buf[1], 0x0d);
	MUST_EQ(buf[15], 0x90);
}

static void
test_err_messages(void)
{
	struct ztinyasm enc;
	char err[128];

	/* call out of rel32 range */
	MUST_EQ(ztinyasm_assemble_ex(0x0, "call 0xffffffff80000000", &enc,
	    fake_resolve, NULL, err, sizeof(err)), -1);
	if (strstr(err, "call target out of rel32 range") == NULL)
		fail("expected call rel32 err", __LINE__);

	/* pa-style length check */
	{
		uint8_t buf[16];
		size_t out_len = 0;

		err[0] = 0;
		MUST_EQ(ztinyasm_patch_ex(0x401000, 4, "jmp 0x401080",
		    buf, sizeof(buf), &out_len, fake_resolve, NULL,
		    err, sizeof(err)), -1);
		if (strstr(err, "exceeds patch length") == NULL)
			fail("expected length err", __LINE__);

		err[0] = 0;
		MUST_EQ(ztinyasm_patch_ex(0x401000, 6, "jmp 0x401080",
		    buf, sizeof(buf), &out_len, fake_resolve, NULL,
		    err, sizeof(err)), 0);
		MUST_EQ(out_len, 6);
		MUST_EQ(buf[0], 0xe9);
		MUST_EQ(buf[5], 0x90);  /* NOP fill */
	}
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
	test_call_rel32();
	test_resolver_callback();
	test_resolver_spaces();
	test_resolver_failure();
	test_no_operand_garbage();
	test_jz_jnz_8_range();
	test_err_messages();
	test_jmpabs();
	test_callabs();
	test_jzabs();
	test_jnzabs();
	test_abs_resolver_failure();
	test_abs_multitoken_operand();
	test_abs_patch_length();

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_tinyasm ok\n");
	return 0;
}
