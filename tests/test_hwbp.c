/*
 * test_hwbp.c - non-ptrace unit tests for the hardware breakpoint
 * table: validation, allocation and DR7 encoding.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_hwbp.h"
#include "zdbg_target.h"

#define CHECK(cond) \
	do { if (!(cond)) { printf("FAIL: %s:%d %s\n", __FILE__, \
	    __LINE__, #cond); return 1; } } while (0)

static int
test_alloc_exec_defaults(void)
{
	struct zhwbp_table ht;
	int id;

	zhwbp_table_init(&ht);
	id = zhwbp_alloc(&ht, 0x400000, ZHWBP_EXEC, 1);
	CHECK(id == 0);
	CHECK(ht.bp[0].state == ZHWBP_DISABLED);
	CHECK(ht.bp[0].kind == ZHWBP_EXEC);
	CHECK(ht.bp[0].len == 1);
	CHECK(ht.bp[0].addr == 0x400000);
	return 0;
}

static int
test_alloc_write_len4(void)
{
	struct zhwbp_table ht;
	int id;

	zhwbp_table_init(&ht);
	id = zhwbp_alloc(&ht, 0x1000, ZHWBP_WRITE, 4);
	CHECK(id == 0);
	CHECK(ht.bp[0].kind == ZHWBP_WRITE);
	CHECK(ht.bp[0].len == 4);
	return 0;
}

static int
test_alloc_rw_len8(void)
{
	struct zhwbp_table ht;
	int id;

	zhwbp_table_init(&ht);
	id = zhwbp_alloc(&ht, 0x2000, ZHWBP_READWRITE, 8);
	CHECK(id == 0);
	CHECK(ht.bp[0].kind == ZHWBP_READWRITE);
	CHECK(ht.bp[0].len == 8);
	return 0;
}

static int
test_reject_exec_bad_len(void)
{
	struct zhwbp_table ht;

	zhwbp_table_init(&ht);
	/* exec must be len 1 */
	CHECK(zhwbp_alloc(&ht, 0x400000, ZHWBP_EXEC, 4) < 0);
	return 0;
}

static int
test_reject_bad_len3(void)
{
	struct zhwbp_table ht;

	zhwbp_table_init(&ht);
	CHECK(zhwbp_alloc(&ht, 0x1000, ZHWBP_WRITE, 3) < 0);
	return 0;
}

static int
test_reject_unaligned(void)
{
	struct zhwbp_table ht;

	zhwbp_table_init(&ht);
	/* 0x1001 % 4 != 0 */
	CHECK(zhwbp_alloc(&ht, 0x1001, ZHWBP_WRITE, 4) < 0);
	CHECK(zhwbp_alloc(&ht, 0x1002, ZHWBP_WRITE, 4) < 0);
	CHECK(zhwbp_alloc(&ht, 0x1003, ZHWBP_READWRITE, 8) < 0);
	return 0;
}

static int
test_alloc_fills_slots_and_fails_when_full(void)
{
	struct zhwbp_table ht;
	int a, b, c, d, e;

	zhwbp_table_init(&ht);
	a = zhwbp_alloc(&ht, 0x1000, ZHWBP_EXEC, 1);
	b = zhwbp_alloc(&ht, 0x2000, ZHWBP_EXEC, 1);
	c = zhwbp_alloc(&ht, 0x3000, ZHWBP_EXEC, 1);
	d = zhwbp_alloc(&ht, 0x4000, ZHWBP_EXEC, 1);
	e = zhwbp_alloc(&ht, 0x5000, ZHWBP_EXEC, 1);
	CHECK(a == 0 && b == 1 && c == 2 && d == 3);
	CHECK(e < 0);
	return 0;
}

static int
test_dr7_build_empty(void)
{
	struct zhwbp_table ht;

	zhwbp_table_init(&ht);
	CHECK(zhwbp_build_dr7(&ht) == 0);
	return 0;
}

static int
test_dr7_build_exec_slot0(void)
{
	struct zhwbp_table ht;
	uint64_t dr7;
	int id;

	zhwbp_table_init(&ht);
	id = zhwbp_alloc(&ht, 0x1000, ZHWBP_EXEC, 1);
	CHECK(id == 0);
	ht.bp[0].state = ZHWBP_ENABLED;
	dr7 = zhwbp_build_dr7(&ht);
	/* L0 set (bit 0); RW0 = 00, LEN0 = 00 */
	CHECK((dr7 & 0x1) == 0x1);
	CHECK(((dr7 >> 16) & 0x3) == 0x0);  /* RW0 exec */
	CHECK(((dr7 >> 18) & 0x3) == 0x0);  /* LEN0 1B */
	/* no other local enable bits */
	CHECK((dr7 & 0x55) == 0x1);
	return 0;
}

static int
test_dr7_build_write_len4_slot1(void)
{
	struct zhwbp_table ht;
	uint64_t dr7;

	zhwbp_table_init(&ht);
	/* Fill slot 0 so the next alloc lands in slot 1. */
	(void)zhwbp_alloc(&ht, 0x2000, ZHWBP_EXEC, 1);
	ht.bp[0].state = ZHWBP_DISABLED;
	/* Force slot 1 allocation */
	{
		int id = zhwbp_alloc(&ht, 0x3000, ZHWBP_WRITE, 4);
		CHECK(id == 1);
		ht.bp[1].state = ZHWBP_ENABLED;
	}
	dr7 = zhwbp_build_dr7(&ht);
	/* slot 0 disabled: L0=0 */
	CHECK((dr7 & 0x1) == 0);
	/* slot 1 enabled: L1 bit = bit 2 */
	CHECK(((dr7 >> 2) & 0x1) == 0x1);
	/* RW1 = 01 (write) at bits 20..21 */
	CHECK(((dr7 >> 20) & 0x3) == 0x1);
	/* LEN1 = 11 (4 bytes) at bits 22..23 */
	CHECK(((dr7 >> 22) & 0x3) == 0x3);
	return 0;
}

static int
test_dr7_build_rw_len8_slot3(void)
{
	struct zhwbp_table ht;
	uint64_t dr7;

	zhwbp_table_init(&ht);
	/* allocate slots 0..3, only slot 3 enabled rw len8 */
	(void)zhwbp_alloc(&ht, 0x1000, ZHWBP_EXEC, 1); /* slot 0 */
	(void)zhwbp_alloc(&ht, 0x2000, ZHWBP_EXEC, 1); /* slot 1 */
	(void)zhwbp_alloc(&ht, 0x3000, ZHWBP_EXEC, 1); /* slot 2 */
	{
		int id = zhwbp_alloc(&ht, 0x4000, ZHWBP_READWRITE, 8);
		CHECK(id == 3);
		ht.bp[3].state = ZHWBP_ENABLED;
	}
	dr7 = zhwbp_build_dr7(&ht);
	/* L3 at bit 6 */
	CHECK(((dr7 >> 6) & 0x1) == 0x1);
	/* RW3 at bits 28..29 == 11 */
	CHECK(((dr7 >> 28) & 0x3) == 0x3);
	/* LEN3 at bits 30..31 == 10 (8 bytes) */
	CHECK(((dr7 >> 30) & 0x3) == 0x2);
	/* L0..L2 off */
	CHECK((dr7 & 0x15) == 0);
	return 0;
}

static int
test_clear_resets_slot(void)
{
	struct zhwbp_table ht;
	struct ztarget dummy;
	int id;

	memset(&dummy, 0, sizeof(dummy));
	zhwbp_table_init(&ht);
	id = zhwbp_alloc(&ht, 0x1000, ZHWBP_WRITE, 4);
	CHECK(id == 0);
	ht.bp[id].state = ZHWBP_ENABLED;
	/* With EMPTY target, clear must succeed without touching
	 * the backend (it is only called when target is stopped). */
	CHECK(zhwbp_clear(&dummy, &ht, id) == 0);
	CHECK(ht.bp[id].state == ZHWBP_EMPTY);
	CHECK(ht.bp[id].addr == 0);
	return 0;
}

static int
test_handle_trap_error_on_dead_target(void)
{
	struct zhwbp_table ht;
	struct ztarget dummy;
	int id = -2;
	uint64_t dr6 = 0;

	memset(&dummy, 0, sizeof(dummy));
	zhwbp_table_init(&ht);
	/* dead target: handler must refuse cleanly */
	CHECK(zhwbp_handle_trap(&dummy, &ht, &id, &dr6) < 0);
	CHECK(id == -1);
	return 0;
}

int
main(void)
{
	if (test_alloc_exec_defaults()) return 1;
	if (test_alloc_write_len4()) return 1;
	if (test_alloc_rw_len8()) return 1;
	if (test_reject_exec_bad_len()) return 1;
	if (test_reject_bad_len3()) return 1;
	if (test_reject_unaligned()) return 1;
	if (test_alloc_fills_slots_and_fails_when_full()) return 1;
	if (test_dr7_build_empty()) return 1;
	if (test_dr7_build_exec_slot0()) return 1;
	if (test_dr7_build_write_len4_slot1()) return 1;
	if (test_dr7_build_rw_len8_slot3()) return 1;
	if (test_clear_resets_slot()) return 1;
	if (test_handle_trap_error_on_dead_target()) return 1;
	printf("OK\n");
	return 0;
}
