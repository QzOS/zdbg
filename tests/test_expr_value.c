/*
 * test_expr_value.c - unit tests for zexpr_eval_value_cb.
 *
 * Drives the value evaluator with an in-memory read callback so
 * the deref forms (u8/u16/u32/u64/ptr/s8/s16/s32) can be exercised
 * without a live target.  Also covers little-endian decoding,
 * read-failure propagation, +/- arithmetic on top of a deref,
 * nested derefs, and the symbol/register fallback path.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_expr.h"
#include "zdbg_filter.h"
#include "zdbg_regs.h"
#include "zdbg_maps.h"
#include "zdbg_symbols.h"

#define CHECK(cond) \
	do { if (!(cond)) { printf("FAIL: %s:%d %s\n", __FILE__, \
	    __LINE__, #cond); return 1; } } while (0)

/*
 * Tiny memory backing.  The callback returns -1 for any address
 * outside [base, base+size).
 */
struct fakemem {
	zaddr_t base;
	size_t size;
	const uint8_t *bytes;
};

static int
fake_read(void *arg, zaddr_t addr, void *buf, size_t len)
{
	struct fakemem *m = (struct fakemem *)arg;

	if (addr < m->base)
		return -1;
	if (addr - m->base > m->size)
		return -1;
	if (len > m->size - (addr - m->base))
		return -1;
	memcpy(buf, m->bytes + (addr - m->base), len);
	return 0;
}

static int
fake_read_fail(void *arg, zaddr_t addr, void *buf, size_t len)
{
	(void)arg; (void)addr; (void)buf; (void)len;
	return -1;
}

static int
test_no_deref_passthrough(void)
{
	struct zregs r;
	zaddr_t v = 0;

	zregs_clear(&r);
	(void)zregs_set_by_name(&r, "rax", 0x1234);

	/* Plain expressions should still work even with NULL read. */
	CHECK(zexpr_eval_value_cb("1234", &r, NULL, NULL,
	    NULL, NULL, &v) == 0);
	CHECK(v == 0x1234);
	CHECK(zexpr_eval_value_cb("rax", &r, NULL, NULL,
	    NULL, NULL, &v) == 0);
	CHECK(v == 0x1234);
	CHECK(zexpr_eval_value_cb("rax+10", &r, NULL, NULL,
	    NULL, NULL, &v) == 0);
	CHECK(v == 0x1244);
	return 0;
}

static int
test_u8_u16_u32_u64(void)
{
	uint8_t bytes[16] = {
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
	};
	struct fakemem m = { 0x1000, sizeof(bytes), bytes };
	struct zregs r;
	zaddr_t v = 0;

	zregs_clear(&r);

	CHECK(zexpr_eval_value_cb("u8(1000)", &r, NULL, NULL,
	    fake_read, &m, &v) == 0);
	CHECK(v == 0x11);

	CHECK(zexpr_eval_value_cb("u16(1000)", &r, NULL, NULL,
	    fake_read, &m, &v) == 0);
	CHECK(v == 0x2211);

	CHECK(zexpr_eval_value_cb("u32(1000)", &r, NULL, NULL,
	    fake_read, &m, &v) == 0);
	CHECK(v == 0x44332211ULL);

	CHECK(zexpr_eval_value_cb("u64(1000)", &r, NULL, NULL,
	    fake_read, &m, &v) == 0);
	CHECK(v == 0x8877665544332211ULL);

	/* ptr is 64-bit on x86-64. */
	CHECK(zexpr_eval_value_cb("ptr(1000)", &r, NULL, NULL,
	    fake_read, &m, &v) == 0);
	CHECK(v == 0x8877665544332211ULL);

	/* poi alias */
	CHECK(zexpr_eval_value_cb("poi(1000)", &r, NULL, NULL,
	    fake_read, &m, &v) == 0);
	CHECK(v == 0x8877665544332211ULL);

	/* Unaligned address. */
	CHECK(zexpr_eval_value_cb("u32(1003)", &r, NULL, NULL,
	    fake_read, &m, &v) == 0);
	CHECK(v == 0x77665544ULL);
	return 0;
}

static int
test_signed_forms(void)
{
	uint8_t bytes[8] = { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 };
	struct fakemem m = { 0x2000, sizeof(bytes), bytes };
	struct zregs r;
	zaddr_t v = 0;

	zregs_clear(&r);

	CHECK(zexpr_eval_value_cb("s8(2000)", &r, NULL, NULL,
	    fake_read, &m, &v) == 0);
	CHECK((int64_t)v == -1);
	CHECK(zexpr_eval_value_cb("s16(2000)", &r, NULL, NULL,
	    fake_read, &m, &v) == 0);
	CHECK((int64_t)v == -1);
	CHECK(zexpr_eval_value_cb("s32(2000)", &r, NULL, NULL,
	    fake_read, &m, &v) == 0);
	CHECK((int64_t)v == -1);
	return 0;
}

static int
test_arith_after_deref(void)
{
	uint8_t bytes[8] = { 0x10, 0x00, 0x00, 0x00, 0, 0, 0, 0 };
	struct fakemem m = { 0x3000, sizeof(bytes), bytes };
	struct zregs r;
	zaddr_t v = 0;

	zregs_clear(&r);

	CHECK(zexpr_eval_value_cb("u32(3000)+1", &r, NULL, NULL,
	    fake_read, &m, &v) == 0);
	CHECK(v == 0x11);

	CHECK(zexpr_eval_value_cb("u32(3000) + 8", &r, NULL, NULL,
	    fake_read, &m, &v) == 0);
	CHECK(v == 0x18);

	/* Reverse direction: number on the left. */
	CHECK(zexpr_eval_value_cb("100 + u32(3000)", &r, NULL, NULL,
	    fake_read, &m, &v) == 0);
	CHECK(v == 0x110);

	/* Subtraction. */
	CHECK(zexpr_eval_value_cb("u32(3000) - 1", &r, NULL, NULL,
	    fake_read, &m, &v) == 0);
	CHECK(v == 0xf);
	return 0;
}

static int
test_nested_deref(void)
{
	/*
	 * 0x4000: pointer 0x4008 (LE)
	 * 0x4008: u32 0xCAFEBABE (LE)
	 */
	uint8_t bytes[16] = {
		0x08, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xbe, 0xba, 0xfe, 0xca, 0x00, 0x00, 0x00, 0x00
	};
	struct fakemem m = { 0x4000, sizeof(bytes), bytes };
	struct zregs r;
	zaddr_t v = 0;

	zregs_clear(&r);

	CHECK(zexpr_eval_value_cb("ptr(4000)", &r, NULL, NULL,
	    fake_read, &m, &v) == 0);
	CHECK(v == 0x4008);

	CHECK(zexpr_eval_value_cb("u32(ptr(4000))", &r, NULL, NULL,
	    fake_read, &m, &v) == 0);
	CHECK(v == 0xCAFEBABE);

	/* Whitespace tolerated around parens. */
	CHECK(zexpr_eval_value_cb("u32 ( ptr ( 4000 ) )", &r, NULL,
	    NULL, fake_read, &m, &v) == 0);
	CHECK(v == 0xCAFEBABE);
	return 0;
}

static int
test_read_failure(void)
{
	struct zregs r;
	zaddr_t v = 0;

	zregs_clear(&r);

	CHECK(zexpr_eval_value_cb("u32(1000)", &r, NULL, NULL,
	    fake_read_fail, NULL, &v) < 0);

	/* Without a callback, deref must fail cleanly. */
	CHECK(zexpr_eval_value_cb("u32(1000)", &r, NULL, NULL,
	    NULL, NULL, &v) < 0);
	return 0;
}

static int
test_inner_uses_register(void)
{
	uint8_t bytes[8] = { 0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 0 };
	struct fakemem m = { 0x5000, sizeof(bytes), bytes };
	struct zregs r;
	zaddr_t v = 0;

	zregs_clear(&r);
	(void)zregs_set_by_name(&r, "rsp", 0x5000);

	CHECK(zexpr_eval_value_cb("u32(rsp)", &r, NULL, NULL,
	    fake_read, &m, &v) == 0);
	CHECK(v == 0xddccbbaaULL);

	CHECK(zexpr_eval_value_cb("u32(rsp+0)", &r, NULL, NULL,
	    fake_read, &m, &v) == 0);
	CHECK(v == 0xddccbbaaULL);
	return 0;
}

static int
test_cond_eval_with_deref(void)
{
	uint8_t bytes[4] = { 0x0a, 0x00, 0x00, 0x00 };
	struct fakemem m = { 0x6000, sizeof(bytes), bytes };
	struct zregs r;
	int res = 0;
	(void)m;

	/*
	 * zcond_eval expects a struct ztarget*; we cannot drive it
	 * directly with a callback.  Confirm the legacy register
	 * path still works (no deref) when the target pointer is
	 * NULL.
	 */
	zregs_clear(&r);
	(void)zregs_set_by_name(&r, "rax", 5);

	CHECK(zcond_eval("rax == 5", NULL, &r, NULL, NULL, &res) == 0);
	CHECK(res == 1);
	CHECK(zcond_eval("rax != 5", NULL, &r, NULL, NULL, &res) == 0);
	CHECK(res == 0);

	/* With NULL target, deref forms must fail safely. */
	CHECK(zcond_eval("u32(6000) == #10", NULL, &r, NULL, NULL,
	    &res) < 0);
	return 0;
}

static int
test_bad_syntax(void)
{
	struct zregs r;
	zaddr_t v = 0;
	uint8_t bytes[4] = { 0, 0, 0, 0 };
	struct fakemem m = { 0x7000, sizeof(bytes), bytes };

	zregs_clear(&r);

	/* Unknown deref keyword. */
	CHECK(zexpr_eval_value_cb("u128(7000)", &r, NULL, NULL,
	    fake_read, &m, &v) < 0);
	/* Unbalanced paren. */
	CHECK(zexpr_eval_value_cb("u32(7000", &r, NULL, NULL,
	    fake_read, &m, &v) < 0);
	/* Trailing garbage after close paren. */
	CHECK(zexpr_eval_value_cb("u32(7000)x", &r, NULL, NULL,
	    fake_read, &m, &v) < 0);
	return 0;
}

int
main(void)
{
	if (test_no_deref_passthrough()) return 1;
	if (test_u8_u16_u32_u64()) return 1;
	if (test_signed_forms()) return 1;
	if (test_arith_after_deref()) return 1;
	if (test_nested_deref()) return 1;
	if (test_read_failure()) return 1;
	if (test_inner_uses_register()) return 1;
	if (test_cond_eval_with_deref()) return 1;
	if (test_bad_syntax()) return 1;
	printf("test_expr_value ok\n");
	return 0;
}
