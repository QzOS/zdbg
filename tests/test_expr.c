/*
 * test_expr.c - tiny expression evaluator tests.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_expr.h"
#include "zdbg_regs.h"

static int failures;

#define CHECK_OK(expr, want) do {                                     \
	zaddr_t _got = 0;                                             \
	int _rc = zexpr_eval((expr), &regs, &_got);                   \
	if (_rc != 0 || _got != (zaddr_t)(want)) {                    \
		fprintf(stderr,                                       \
		    "FAIL %s:%d '%s' rc=%d got=%llx want=%llx\n",     \
		    __FILE__, __LINE__, (expr), _rc,                  \
		    (unsigned long long)_got,                         \
		    (unsigned long long)(zaddr_t)(want));             \
		failures++;                                           \
	}                                                             \
} while (0)

#define CHECK_FAIL(expr) do {                                         \
	zaddr_t _got = 0;                                             \
	int _rc = zexpr_eval((expr), &regs, &_got);                   \
	if (_rc == 0) {                                               \
		fprintf(stderr,                                       \
		    "FAIL %s:%d '%s' unexpectedly succeeded (got %llx)\n", \
		    __FILE__, __LINE__, (expr),                       \
		    (unsigned long long)_got);                        \
		failures++;                                           \
	}                                                             \
} while (0)

int
main(void)
{
	struct zregs regs;
	zregs_clear(&regs);
	regs.rip = 0x400000;
	regs.rsp = 0x7fff0000;
	regs.rax = 0x1000;

	CHECK_OK("401000", 0x401000);
	CHECK_OK("0x401000", 0x401000);
	CHECK_OK("0X401000", 0x401000);
	CHECK_OK("401000h", 0x401000);
	CHECK_OK("#16", 16);
	CHECK_OK("#100", 100);
	CHECK_OK("rip", 0x400000);
	CHECK_OK("RIP", 0x400000);
	CHECK_OK("pc", 0x400000);
	CHECK_OK("sp", 0x7fff0000);
	CHECK_OK("rip+10", 0x400010);
	CHECK_OK("rsp-20", 0x7fff0000 - 0x20);
	CHECK_OK("rax+8", 0x1008);
	CHECK_OK("  rax  +  8  ", 0x1008);
	CHECK_OK("#10+#5", 15);

	CHECK_FAIL("");
	CHECK_FAIL("bogus_reg");
	CHECK_FAIL("rip*2");
	CHECK_FAIL("rip+");
	CHECK_FAIL("(rip)");

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_expr ok\n");
	return 0;
}
