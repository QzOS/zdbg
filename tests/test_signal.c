/*
 * test_signal.c - signal subsystem unit tests: name parsing,
 * formatting, default policy, and handle-style policy updates.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_signal.h"

static int failures;

#define CHECK(cond, msg) do {                                         \
	if (!(cond)) {                                                \
		fprintf(stderr, "FAIL %s:%d %s\n",                    \
		    __FILE__, __LINE__, (msg));                       \
		failures++;                                           \
	}                                                             \
} while (0)

#define CHECK_PARSE_OK(s, want) do {                                  \
	int _g = -1;                                                  \
	int _rc = zsig_parse((s), &_g);                               \
	if (_rc != 0 || _g != (want)) {                               \
		fprintf(stderr,                                       \
		    "FAIL %s:%d parse '%s' rc=%d got=%d want=%d\n",   \
		    __FILE__, __LINE__, (s), _rc, _g, (int)(want));   \
		failures++;                                           \
	}                                                             \
} while (0)

#define CHECK_PARSE_FAIL(s) do {                                      \
	int _g = -1;                                                  \
	int _rc = zsig_parse((s), &_g);                               \
	if (_rc == 0) {                                               \
		fprintf(stderr,                                       \
		    "FAIL %s:%d parse '%s' unexpectedly ok, got %d\n",\
		    __FILE__, __LINE__, (s), _g);                     \
		failures++;                                           \
	}                                                             \
} while (0)

int
main(void)
{
	struct zsig_table zt;
	const struct zsig_policy *p;

	/* name parsing */
	CHECK_PARSE_OK("SIGSEGV", 11);
	CHECK_PARSE_OK("sigsegv", 11);
	CHECK_PARSE_OK("SEGV", 11);
	CHECK_PARSE_OK("segv", 11);
	CHECK_PARSE_OK("11", 11);
	CHECK_PARSE_OK("#11", 11);
	CHECK_PARSE_OK("0xb", 11);
	CHECK_PARSE_OK("0XB", 11);
	CHECK_PARSE_OK("  SIGUSR1  ", 10);
	CHECK_PARSE_OK("0", 0);
	CHECK_PARSE_FAIL("");
	CHECK_PARSE_FAIL("SIGWAT");
	CHECK_PARSE_FAIL("9999");
	CHECK_PARSE_FAIL("0xzz");
	CHECK_PARSE_FAIL("-3");

	/* naming */
	CHECK(strcmp(zsig_name(11), "SIGSEGV") == 0,
	    "zsig_name(11) != SIGSEGV");
	CHECK(strcmp(zsig_name(10), "SIGUSR1") == 0,
	    "zsig_name(10) != SIGUSR1");
	CHECK(strcmp(zsig_name(9999), "SIG?") == 0,
	    "zsig_name(9999) != SIG?");

	/* default policies */
	zsig_table_init(&zt);
	p = zsig_get_policy(&zt, 11); /* SIGSEGV */
	CHECK(p != NULL && p->stop && p->pass && p->print,
	    "SIGSEGV default policy wrong");
	p = zsig_get_policy(&zt, 5);  /* SIGTRAP */
	CHECK(p != NULL && p->stop && !p->pass && !p->print,
	    "SIGTRAP default policy wrong");
	p = zsig_get_policy(&zt, 17); /* SIGCHLD */
	CHECK(p != NULL && !p->stop && p->pass && !p->print,
	    "SIGCHLD default policy wrong");
	p = zsig_get_policy(&zt, 28); /* SIGWINCH */
	CHECK(p != NULL && !p->stop && p->pass && !p->print,
	    "SIGWINCH default policy wrong");
	p = zsig_get_policy(&zt, 19); /* SIGSTOP */
	CHECK(p != NULL && p->stop && !p->pass && p->print,
	    "SIGSEGV default policy wrong");
	CHECK(zsig_get_policy(&zt, 0) == NULL,
	    "policy for signal 0 should be NULL");
	CHECK(zsig_get_policy(&zt, ZDBG_MAX_SIGNALS) == NULL,
	    "policy for out-of-range should be NULL");

	/* selective updates: only stop flag changes */
	CHECK(zsig_set_policy(&zt, 10, 1, 0, 0, 0, 0, 0) == 0,
	    "set_policy(SIGUSR1, nostop) failed");
	p = zsig_get_policy(&zt, 10);
	CHECK(p != NULL && !p->stop && p->pass && p->print,
	    "SIGUSR1 nostop should not touch pass/print");

	/* selective updates: only pass flag changes */
	CHECK(zsig_set_policy(&zt, 10, 0, 0, 1, 0, 0, 0) == 0,
	    "set_policy(SIGUSR1, nopass) failed");
	p = zsig_get_policy(&zt, 10);
	CHECK(p != NULL && !p->stop && !p->pass && p->print,
	    "SIGUSR1 nopass should not touch stop/print");

	/* selective updates: only print flag changes */
	CHECK(zsig_set_policy(&zt, 10, 0, 0, 0, 0, 1, 0) == 0,
	    "set_policy(SIGUSR1, noprint) failed");
	p = zsig_get_policy(&zt, 10);
	CHECK(p != NULL && !p->stop && !p->pass && !p->print,
	    "SIGUSR1 noprint should not touch stop/pass");

	/* out-of-range set */
	CHECK(zsig_set_policy(&zt, 0, 1, 1, 0, 0, 0, 0) < 0,
	    "set_policy(0) should fail");
	CHECK(zsig_set_policy(&zt, ZDBG_MAX_SIGNALS, 1, 1, 0, 0, 0, 0) < 0,
	    "set_policy(MAX) should fail");

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_signal ok\n");
	return 0;
}
