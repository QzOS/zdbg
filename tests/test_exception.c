/*
 * test_exception.c - Windows exception subsystem unit tests:
 * name parsing/formatting, default policy, and handle-style
 * policy updates.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_exception.h"

static int failures;

#define CHECK(cond, msg) do {                                         \
	if (!(cond)) {                                                \
		fprintf(stderr, "FAIL %s:%d %s\n",                    \
		    __FILE__, __LINE__, (msg));                       \
		failures++;                                           \
	}                                                             \
} while (0)

#define CHECK_PARSE_OK(s, want) do {                                  \
	uint32_t _g = 0;                                              \
	int _rc = zexc_parse((s), &_g);                               \
	if (_rc != 0 || _g != (uint32_t)(want)) {                     \
		fprintf(stderr,                                       \
		    "FAIL %s:%d parse '%s' rc=%d got=0x%x want=0x%x\n",\
		    __FILE__, __LINE__, (s), _rc,                     \
		    (unsigned int)_g, (unsigned int)(want));          \
		failures++;                                           \
	}                                                             \
} while (0)

#define CHECK_PARSE_FAIL(s) do {                                      \
	uint32_t _g = 0;                                              \
	int _rc = zexc_parse((s), &_g);                               \
	if (_rc == 0) {                                               \
		fprintf(stderr,                                       \
		    "FAIL %s:%d parse '%s' unexpectedly ok, got 0x%x\n",\
		    __FILE__, __LINE__, (s), (unsigned int)_g);       \
		failures++;                                           \
	}                                                             \
} while (0)

int
main(void)
{
	struct zexc_table xt;
	const struct zexc_policy *p;

	/* name parsing: macro form */
	CHECK_PARSE_OK("EXCEPTION_ACCESS_VIOLATION", 0xc0000005u);
	CHECK_PARSE_OK("exception_access_violation", 0xc0000005u);
	CHECK_PARSE_OK("access_violation", 0xc0000005u);
	CHECK_PARSE_OK("Access_Violation", 0xc0000005u);
	CHECK_PARSE_OK("av", 0xc0000005u);

	CHECK_PARSE_OK("EXCEPTION_ILLEGAL_INSTRUCTION", 0xc000001du);
	CHECK_PARSE_OK("illegal_instruction", 0xc000001du);
	CHECK_PARSE_OK("EXCEPTION_GUARD_PAGE", 0x80000001u);
	CHECK_PARSE_OK("guard_page", 0x80000001u);
	CHECK_PARSE_OK("MSVC_CPP_EXCEPTION", 0xe06d7363u);
	CHECK_PARSE_OK("msvc_cpp", 0xe06d7363u);
	CHECK_PARSE_OK("cpp", 0xe06d7363u);

	/* numeric forms */
	CHECK_PARSE_OK("0xc0000005", 0xc0000005u);
	CHECK_PARSE_OK("0XC0000005", 0xc0000005u);
	CHECK_PARSE_OK("c0000005", 0xc0000005u);
	CHECK_PARSE_OK("C0000005", 0xc0000005u);
	/* #N: explicit decimal.  EXCEPTION_ACCESS_VIOLATION =
	 * 0xc0000005 = 3221225477. */
	CHECK_PARSE_OK("#3221225477", 0xc0000005u);
	CHECK_PARSE_OK("  EXCEPTION_ACCESS_VIOLATION  ", 0xc0000005u);

	CHECK_PARSE_FAIL("");
	CHECK_PARSE_FAIL("not_an_exception");
	CHECK_PARSE_FAIL("0xzz");
	CHECK_PARSE_FAIL("-1");

	/* naming */
	CHECK(strcmp(zexc_name(0xc0000005u),
	    "EXCEPTION_ACCESS_VIOLATION") == 0,
	    "zexc_name(0xc0000005) != EXCEPTION_ACCESS_VIOLATION");
	CHECK(strcmp(zexc_name(0xe06d7363u),
	    "MSVC_CPP_EXCEPTION") == 0,
	    "zexc_name(0xe06d7363) != MSVC_CPP_EXCEPTION");
	CHECK(strcmp(zexc_name(0xdeadbeefu), "EXCEPTION?") == 0,
	    "zexc_name(unknown) != EXCEPTION?");

	/* default policies */
	zexc_table_init(&xt);

	/* AV: stop yes pass yes print yes */
	p = zexc_get_policy(&xt, 0xc0000005u);
	CHECK(p != NULL && p->stop && p->pass && p->print,
	    "AV default policy wrong");

	/* guard page: stop no pass yes print no */
	p = zexc_get_policy(&xt, 0x80000001u);
	CHECK(p != NULL && !p->stop && p->pass && !p->print,
	    "guard page default policy wrong");

	/* MSVC C++ exception: stop no pass yes print no */
	p = zexc_get_policy(&xt, 0xe06d7363u);
	CHECK(p != NULL && !p->stop && p->pass && !p->print,
	    "MSVC C++ default policy wrong");

	/* Breakpoint/single-step are debugger-internal. */
	p = zexc_get_policy(&xt, 0x80000003u);
	CHECK(p != NULL && p->stop && !p->pass && !p->print,
	    "EXCEPTION_BREAKPOINT default policy wrong");
	p = zexc_get_policy(&xt, 0x80000004u);
	CHECK(p != NULL && p->stop && !p->pass && !p->print,
	    "EXCEPTION_SINGLE_STEP default policy wrong");

	/* Unknown code falls through to defpol: stop yes pass yes
	 * print yes. */
	p = zexc_get_policy(&xt, 0xdeadbeefu);
	CHECK(p != NULL && p->stop && p->pass && p->print,
	    "unknown exception default policy wrong");

	/* Selective updates: only stop flag changes. */
	CHECK(zexc_set_policy(&xt, 0xc0000005u, 1, 0, 0, 0, 0, 0) == 0,
	    "set_policy(AV, nostop) failed");
	p = zexc_get_policy(&xt, 0xc0000005u);
	CHECK(p != NULL && !p->stop && p->pass && p->print,
	    "AV nostop should not touch pass/print");

	/* Selective updates: only pass flag changes. */
	CHECK(zexc_set_policy(&xt, 0xc0000005u, 0, 0, 1, 0, 0, 0) == 0,
	    "set_policy(AV, nopass) failed");
	p = zexc_get_policy(&xt, 0xc0000005u);
	CHECK(p != NULL && !p->stop && !p->pass && p->print,
	    "AV nopass should not touch stop/print");

	/* Selective updates: only print flag changes. */
	CHECK(zexc_set_policy(&xt, 0xc0000005u, 0, 0, 0, 0, 1, 0) == 0,
	    "set_policy(AV, noprint) failed");
	p = zexc_get_policy(&xt, 0xc0000005u);
	CHECK(p != NULL && !p->stop && !p->pass && !p->print,
	    "AV noprint should not touch stop/pass");

	/* New code: creates a policy slot. */
	CHECK(zexc_set_policy(&xt, 0xe1234567u, 1, 0, 1, 1, 1, 1) == 0,
	    "set_policy(0xe1234567) failed");
	p = zexc_get_policy(&xt, 0xe1234567u);
	CHECK(p != NULL && !p->stop && p->pass && p->print,
	    "0xe1234567 new policy wrong");

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_exception ok\n");
	return 0;
}
