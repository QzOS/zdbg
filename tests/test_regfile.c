/*
 * test_regfile.c - tests for the generic register-file view.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_regfile.h"
#include "zdbg_regs.h"
#include "zdbg_expr.h"
#include "zdbg_filter.h"

static int failures;

#define EXPECT_EQ(got, want) do {                                    \
	uint64_t _g = (uint64_t)(got);                               \
	uint64_t _w = (uint64_t)(want);                              \
	if (_g != _w) {                                              \
		fprintf(stderr,                                      \
		    "FAIL %s:%d expected %llx, got %llx\n",          \
		    __FILE__, __LINE__,                              \
		    (unsigned long long)_w,                          \
		    (unsigned long long)_g);                         \
		failures++;                                          \
	}                                                            \
} while (0)

#define EXPECT_OK(call) do {                                         \
	int _rc = (call);                                            \
	if (_rc != 0) {                                              \
		fprintf(stderr,                                      \
		    "FAIL %s:%d expected ok, got %d\n",              \
		    __FILE__, __LINE__, _rc);                        \
		failures++;                                          \
	}                                                            \
} while (0)

#define EXPECT_FAIL(call) do {                                       \
	int _rc = (call);                                            \
	if (_rc == 0) {                                              \
		fprintf(stderr,                                      \
		    "FAIL %s:%d expected failure, got ok\n",         \
		    __FILE__, __LINE__);                             \
		failures++;                                          \
	}                                                            \
} while (0)

static void
fill_zregs(struct zregs *r)
{
	zregs_clear(r);
	r->rax = 0x1111111111111111ULL;
	r->rbx = 0x2222222222222222ULL;
	r->rcx = 0x3333333333333333ULL;
	r->rdx = 0x4444444444444444ULL;
	r->rsi = 0x5555555555555555ULL;
	r->rdi = 0x6666666666666666ULL;
	r->rbp = 0x7777777777777777ULL;
	r->rsp = 0x8888888888888888ULL;
	r->r8  = 0x9999999999999999ULL;
	r->r9  = 0xAAAAAAAAAAAAAAAAULL;
	r->r10 = 0xBBBBBBBBBBBBBBBBULL;
	r->r11 = 0xCCCCCCCCCCCCCCCCULL;
	r->r12 = 0xDDDDDDDDDDDDDDDDULL;
	r->r13 = 0xEEEEEEEEEEEEEEEEULL;
	r->r14 = 0xFFFFFFFFFFFFFFFFULL;
	r->r15 = 0x1010101010101010ULL;
	r->rip = 0x401000ULL;
	r->rflags = 0x202ULL;
}

static void
test_x86_64_init_and_descriptors(void)
{
	struct zreg_file rf;

	zregfile_init(&rf, ZARCH_X86_64);
	EXPECT_EQ(rf.arch, ZARCH_X86_64);
	EXPECT_EQ(rf.count, 18);
	EXPECT_EQ(rf.desc_count, 18);
	if (rf.desc == NULL || rf.aliases == NULL) {
		fprintf(stderr, "FAIL %s: NULL desc/aliases\n", __func__);
		failures++;
	}
}

static void
test_from_to_zregs(void)
{
	struct zregs in;
	struct zregs out;
	struct zreg_file rf;

	fill_zregs(&in);
	memset(&out, 0, sizeof(out));
	EXPECT_OK(zregfile_from_zregs(&rf, ZARCH_X86_64, &in));
	EXPECT_OK(zregfile_to_zregs(&rf, &out));
	if (memcmp(&in, &out, sizeof(in)) != 0) {
		fprintf(stderr, "FAIL %s: roundtrip mismatch\n", __func__);
		failures++;
	}
}

static void
test_get_set(void)
{
	struct zregs in;
	struct zreg_file rf;
	uint64_t v = 0;

	fill_zregs(&in);
	EXPECT_OK(zregfile_from_zregs(&rf, ZARCH_X86_64, &in));

	EXPECT_OK(zregfile_get(&rf, "rax", &v));
	EXPECT_EQ(v, 0x1111111111111111ULL);
	EXPECT_OK(zregfile_get(&rf, "rip", &v));
	EXPECT_EQ(v, 0x401000ULL);
	EXPECT_OK(zregfile_get(&rf, "rsp", &v));
	EXPECT_EQ(v, 0x8888888888888888ULL);
	EXPECT_OK(zregfile_get(&rf, "rbp", &v));
	EXPECT_EQ(v, 0x7777777777777777ULL);
	/* case-insensitive */
	EXPECT_OK(zregfile_get(&rf, "RIP", &v));
	EXPECT_EQ(v, 0x401000ULL);
	/* unknown */
	EXPECT_FAIL(zregfile_get(&rf, "bogus", &v));

	EXPECT_OK(zregfile_set(&rf, "rax", 0xCAFEULL));
	EXPECT_OK(zregfile_get(&rf, "rax", &v));
	EXPECT_EQ(v, 0xCAFEULL);
	EXPECT_OK(zregfile_set(&rf, "rip", 0xDEADBEEFULL));
	EXPECT_OK(zregfile_get(&rf, "rip", &v));
	EXPECT_EQ(v, 0xDEADBEEFULL);
}

static void
test_aliases(void)
{
	struct zregs in;
	struct zreg_file rf;
	uint64_t v = 0;

	fill_zregs(&in);
	EXPECT_OK(zregfile_from_zregs(&rf, ZARCH_X86_64, &in));

	/* pc -> rip, sp -> rsp, fp -> rbp */
	EXPECT_OK(zregfile_get(&rf, "pc", &v));
	EXPECT_EQ(v, 0x401000ULL);
	EXPECT_OK(zregfile_get(&rf, "sp", &v));
	EXPECT_EQ(v, 0x8888888888888888ULL);
	EXPECT_OK(zregfile_get(&rf, "fp", &v));
	EXPECT_EQ(v, 0x7777777777777777ULL);
	EXPECT_OK(zregfile_get(&rf, "ip", &v));
	EXPECT_EQ(v, 0x401000ULL);
	EXPECT_OK(zregfile_get(&rf, "flags", &v));
	EXPECT_EQ(v, 0x202ULL);

	/* alias write must not duplicate state: setting pc updates rip */
	EXPECT_OK(zregfile_set(&rf, "pc", 0x12345ULL));
	EXPECT_OK(zregfile_get(&rf, "rip", &v));
	EXPECT_EQ(v, 0x12345ULL);
}

static void
test_roles(void)
{
	struct zregs in;
	struct zreg_file rf;
	uint64_t v = 0;
	const char *n;

	fill_zregs(&in);
	EXPECT_OK(zregfile_from_zregs(&rf, ZARCH_X86_64, &in));

	EXPECT_OK(zregfile_get_role(&rf, ZREG_ROLE_PC, &v));
	EXPECT_EQ(v, 0x401000ULL);
	EXPECT_OK(zregfile_get_role(&rf, ZREG_ROLE_SP, &v));
	EXPECT_EQ(v, 0x8888888888888888ULL);
	EXPECT_OK(zregfile_get_role(&rf, ZREG_ROLE_FP, &v));
	EXPECT_EQ(v, 0x7777777777777777ULL);

	n = zregfile_role_name(&rf, ZREG_ROLE_PC);
	if (n == NULL || strcmp(n, "rip") != 0) {
		fprintf(stderr, "FAIL %s PC name=%s\n", __func__,
		    n ? n : "(null)");
		failures++;
	}
	n = zregfile_role_name(&rf, ZREG_ROLE_SP);
	if (n == NULL || strcmp(n, "rsp") != 0) {
		fprintf(stderr, "FAIL %s SP name=%s\n", __func__,
		    n ? n : "(null)");
		failures++;
	}
	n = zregfile_role_name(&rf, ZREG_ROLE_FP);
	if (n == NULL || strcmp(n, "rbp") != 0) {
		fprintf(stderr, "FAIL %s FP name=%s\n", __func__,
		    n ? n : "(null)");
		failures++;
	}

	EXPECT_OK(zregfile_set_role(&rf, ZREG_ROLE_PC, 0xABCDEFULL));
	EXPECT_OK(zregfile_get(&rf, "rip", &v));
	EXPECT_EQ(v, 0xABCDEFULL);
}

static void
test_aarch64_stub(void)
{
	struct zreg_file rf;
	uint64_t v = 0;

	zregfile_init(&rf, ZARCH_AARCH64);
	EXPECT_EQ(rf.arch, ZARCH_AARCH64);
	EXPECT_EQ(rf.count, 0);
	EXPECT_FAIL(zregfile_get(&rf, "pc", &v));
	EXPECT_FAIL(zregfile_get(&rf, "x0", &v));
	EXPECT_FAIL(zregfile_set(&rf, "x0", 0));
	EXPECT_FAIL(zregfile_get_role(&rf, ZREG_ROLE_PC, &v));
	if (zregfile_role_name(&rf, ZREG_ROLE_PC) != NULL) {
		fprintf(stderr, "FAIL %s: AArch64 PC name not NULL\n",
		    __func__);
		failures++;
	}
	/* should not crash */
	zregfile_print(&rf);
}

static void
test_print_does_not_crash(void)
{
	struct zregs in;
	struct zreg_file rf;

	fill_zregs(&in);
	EXPECT_OK(zregfile_from_zregs(&rf, ZARCH_X86_64, &in));
	zregfile_print(&rf);
}

static void
test_expr_rf(void)
{
	struct zregs in;
	struct zreg_file rf;
	zaddr_t v = 0;

	fill_zregs(&in);
	in.rax = 0x1000;
	in.rip = 0x400000;
	in.rsp = 0x7fff0000;
	in.rbp = 0x7fff1000;
	EXPECT_OK(zregfile_from_zregs(&rf, ZARCH_X86_64, &in));

	EXPECT_OK(zexpr_eval_rf("rax", &rf, &v));
	EXPECT_EQ(v, 0x1000);
	EXPECT_OK(zexpr_eval_rf("rip+10", &rf, &v));
	EXPECT_EQ(v, 0x400010);
	EXPECT_OK(zexpr_eval_rf("pc", &rf, &v));
	EXPECT_EQ(v, 0x400000);
	EXPECT_OK(zexpr_eval_rf("sp", &rf, &v));
	EXPECT_EQ(v, 0x7fff0000);
	EXPECT_OK(zexpr_eval_rf("fp", &rf, &v));
	EXPECT_EQ(v, 0x7fff1000);

	/* numbers still work without registers */
	EXPECT_OK(zexpr_eval_rf("0x1234", NULL, &v));
	EXPECT_EQ(v, 0x1234);
	EXPECT_FAIL(zexpr_eval_rf("rax", NULL, &v));

	/* symbol-aware variant with no symbols */
	EXPECT_OK(zexpr_eval_symbols_rf("rax+8", &rf, NULL, NULL, &v));
	EXPECT_EQ(v, 0x1008);
}

static void
test_cond_rf(void)
{
	struct zregs in;
	struct zreg_file rf;
	int res = 0;

	fill_zregs(&in);
	in.rax = 3;
	in.rip = 0x401000;
	EXPECT_OK(zregfile_from_zregs(&rf, ZARCH_X86_64, &in));

	EXPECT_OK(zcond_eval_rf("rax == 3", NULL, &rf, NULL, NULL, &res));
	EXPECT_EQ(res, 1);
	EXPECT_OK(zcond_eval_rf("rax != 3", NULL, &rf, NULL, NULL, &res));
	EXPECT_EQ(res, 0);
	EXPECT_OK(zcond_eval_rf("pc != 0", NULL, &rf, NULL, NULL, &res));
	EXPECT_EQ(res, 1);
	EXPECT_OK(zcond_eval_rf("pc == 401000", NULL, &rf, NULL, NULL,
	    &res));
	EXPECT_EQ(res, 1);
	EXPECT_OK(zcond_eval_rf("rax", NULL, &rf, NULL, NULL, &res));
	EXPECT_EQ(res, 1);
}

int
main(void)
{
	test_x86_64_init_and_descriptors();
	test_from_to_zregs();
	test_get_set();
	test_aliases();
	test_roles();
	test_aarch64_stub();
	test_print_does_not_crash();
	test_expr_rf();
	test_cond_rf();

	if (failures) {
		fprintf(stderr, "test_regfile: %d failures\n", failures);
		return 1;
	}
	printf("test_regfile ok\n");
	return 0;
}
