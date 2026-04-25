/*
 * test_filter.c - unit tests for struct zstop_filter and the
 * tiny condition evaluator.  No live target needed; both pieces
 * are pure data + zexpr_eval_symbols.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_filter.h"
#include "zdbg_regs.h"
#include "zdbg_maps.h"
#include "zdbg_symbols.h"

#define CHECK(cond) \
	do { if (!(cond)) { printf("FAIL: %s:%d %s\n", __FILE__, \
	    __LINE__, #cond); return 1; } } while (0)

static int
test_filter_init_zero(void)
{
	struct zstop_filter f;

	memset(&f, 0xa5, sizeof(f));
	zfilter_init(&f);
	CHECK(f.hits == 0);
	CHECK(f.ignore == 0);
	CHECK(f.has_cond == 0);
	CHECK(f.cond[0] == 0);
	return 0;
}

static int
test_filter_set_clear_condition(void)
{
	struct zstop_filter f;

	zfilter_init(&f);
	CHECK(zfilter_set_condition(&f, "rax == 0") == 0);
	CHECK(f.has_cond == 1);
	CHECK(strcmp(f.cond, "rax == 0") == 0);

	zfilter_clear_condition(&f);
	CHECK(f.has_cond == 0);
	CHECK(f.cond[0] == 0);

	/* empty string clears */
	(void)zfilter_set_condition(&f, "rip");
	CHECK(f.has_cond == 1);
	CHECK(zfilter_set_condition(&f, NULL) == 0);
	CHECK(f.has_cond == 0);
	(void)zfilter_set_condition(&f, "rip");
	CHECK(zfilter_set_condition(&f, "") == 0);
	CHECK(f.has_cond == 0);
	return 0;
}

static int
test_filter_condition_too_long(void)
{
	struct zstop_filter f;
	char buf[ZDBG_FILTER_EXPR_MAX + 8];
	size_t i;

	zfilter_init(&f);
	for (i = 0; i < sizeof(buf) - 1; i++)
		buf[i] = 'a';
	buf[sizeof(buf) - 1] = 0;
	CHECK(zfilter_set_condition(&f, buf) < 0);
	CHECK(f.has_cond == 0);
	return 0;
}

static int
test_filter_set_ignore_and_reset(void)
{
	struct zstop_filter f;

	zfilter_init(&f);
	zfilter_set_ignore(&f, 5);
	CHECK(f.ignore == 5);
	zfilter_set_ignore(&f, 1);
	CHECK(f.ignore == 1); /* replaces, not adds */
	f.hits = 42;
	zfilter_reset_hits(&f);
	CHECK(f.hits == 0);
	return 0;
}

/* condition evaluator */

static int
test_cond_no_operator_truth(void)
{
	struct zregs r;
	int res = -1;

	memset(&r, 0, sizeof(r));
	r.rax = 7;
	CHECK(zcond_eval("rax", &r, NULL, NULL, &res) == 0);
	CHECK(res == 1);

	res = -1;
	r.rax = 0;
	CHECK(zcond_eval("rax", &r, NULL, NULL, &res) == 0);
	CHECK(res == 0);

	res = -1;
	CHECK(zcond_eval("#0", &r, NULL, NULL, &res) == 0);
	CHECK(res == 0);

	res = -1;
	CHECK(zcond_eval("#1", &r, NULL, NULL, &res) == 0);
	CHECK(res == 1);
	return 0;
}

static int
test_cond_eq_ne(void)
{
	struct zregs r;
	int res = -1;

	memset(&r, 0, sizeof(r));
	r.rax = 0x10;
	r.rdi = 3;

	CHECK(zcond_eval("rax == 10", &r, NULL, NULL, &res) == 0);
	CHECK(res == 1);
	res = -1;
	CHECK(zcond_eval("rax==10", &r, NULL, NULL, &res) == 0);
	CHECK(res == 1);
	res = -1;
	CHECK(zcond_eval("rax != 10", &r, NULL, NULL, &res) == 0);
	CHECK(res == 0);
	res = -1;
	CHECK(zcond_eval("rdi == #3", &r, NULL, NULL, &res) == 0);
	CHECK(res == 1);
	res = -1;
	CHECK(zcond_eval("rdi != #2", &r, NULL, NULL, &res) == 0);
	CHECK(res == 1);
	return 0;
}

static int
test_cond_lt_le_gt_ge(void)
{
	struct zregs r;
	int res = -1;

	memset(&r, 0, sizeof(r));
	r.rax = 5;

	CHECK(zcond_eval("rax < #6", &r, NULL, NULL, &res) == 0);
	CHECK(res == 1);
	res = -1;
	CHECK(zcond_eval("rax <= #5", &r, NULL, NULL, &res) == 0);
	CHECK(res == 1);
	res = -1;
	CHECK(zcond_eval("rax > #5", &r, NULL, NULL, &res) == 0);
	CHECK(res == 0);
	res = -1;
	CHECK(zcond_eval("rax >= #5", &r, NULL, NULL, &res) == 0);
	CHECK(res == 1);
	res = -1;
	CHECK(zcond_eval("rax<#100", &r, NULL, NULL, &res) == 0);
	CHECK(res == 1);
	return 0;
}

static int
test_cond_invalid(void)
{
	struct zregs r;
	int res = -1;

	memset(&r, 0, sizeof(r));
	/* unknown register */
	CHECK(zcond_eval("nopereg == 0", &r, NULL, NULL, &res) < 0);
	/* empty operand */
	CHECK(zcond_eval("== 5", &r, NULL, NULL, &res) < 0);
	CHECK(zcond_eval("rax ==", &r, NULL, NULL, &res) < 0);
	CHECK(zcond_eval("", &r, NULL, NULL, &res) < 0);
	CHECK(zcond_eval(NULL, &r, NULL, NULL, &res) < 0);
	return 0;
}

static int
test_cond_register_offset(void)
{
	struct zregs r;
	int res = -1;

	memset(&r, 0, sizeof(r));
	r.rip = 0x401000;

	CHECK(zcond_eval("rip == 401000", &r, NULL, NULL, &res) == 0);
	CHECK(res == 1);
	res = -1;
	/* unsigned compare: rsp 0 < 0x100 */
	CHECK(zcond_eval("rsp < 100", &r, NULL, NULL, &res) == 0);
	CHECK(res == 1);
	return 0;
}

int
main(void)
{
	if (test_filter_init_zero()) return 1;
	if (test_filter_set_clear_condition()) return 1;
	if (test_filter_condition_too_long()) return 1;
	if (test_filter_set_ignore_and_reset()) return 1;
	if (test_cond_no_operator_truth()) return 1;
	if (test_cond_eq_ne()) return 1;
	if (test_cond_lt_le_gt_ge()) return 1;
	if (test_cond_invalid()) return 1;
	if (test_cond_register_offset()) return 1;
	printf("test_filter ok\n");
	return 0;
}
