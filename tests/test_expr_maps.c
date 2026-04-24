/*
 * test_expr_maps.c - map-aware expression evaluator tests.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_expr.h"
#include "zdbg_maps.h"
#include "zdbg_regs.h"

static int failures;

#define CHECK_OK(expr, want) do {                                     \
	zaddr_t _got = 0;                                             \
	int _rc = zexpr_eval_maps((expr), &regs, &mt, &_got);         \
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
	int _rc = zexpr_eval_maps((expr), &regs, &mt, &_got);         \
	if (_rc == 0) {                                               \
		fprintf(stderr,                                       \
		    "FAIL %s:%d '%s' unexpectedly succeeded (got %llx)\n", \
		    __FILE__, __LINE__, (expr),                       \
		    (unsigned long long)_got);                        \
		failures++;                                           \
	}                                                             \
} while (0)

static void
add_map(struct zmap_table *mt, zaddr_t start, zaddr_t end,
    const char *perms, const char *name)
{
	struct zmap *m = &mt->maps[mt->count++];
	memset(m, 0, sizeof(*m));
	m->start = start;
	m->end = end;
	m->offset = 0;
	strncpy(m->perms, perms, 4);
	m->perms[4] = 0;
	strncpy(m->name, name, ZDBG_MAP_NAME_MAX - 1);
}

int
main(void)
{
	struct zregs regs;
	struct zmap_table mt;

	zregs_clear(&regs);
	regs.rip = 0x400000;
	regs.rax = 0x1000;

	zmaps_init(&mt);
	add_map(&mt, 0x555555554000ULL, 0x555555555000ULL, "r--p",
	    "/home/me/testprog");
	add_map(&mt, 0x555555555000ULL, 0x555555556000ULL, "r-xp",
	    "/home/me/testprog");
	add_map(&mt, 0x7ffff7dd0000ULL, 0x7ffff7f9b000ULL, "r-xp",
	    "/lib/x86_64-linux-gnu/libc.so.6");
	add_map(&mt, 0x7ffffffde000ULL, 0x7ffffffff000ULL, "rw-p",
	    "[stack]");
	zmaps_set_main_hint(&mt, "/home/me/testprog");

	/* existing numeric / register expressions still work */
	CHECK_OK("401000", 0x401000);
	CHECK_OK("0x401000", 0x401000);
	CHECK_OK("401000h", 0x401000);
	CHECK_OK("#16", 16);
	CHECK_OK("rip", 0x400000);
	CHECK_OK("rip+10", 0x400010);
	CHECK_OK("rax+8", 0x1008);

	/* module base / offset */
	CHECK_OK("main", 0x555555555000ULL);
	CHECK_OK("main+1180", 0x555555555000ULL + 0x1180);
	CHECK_OK("main-10", 0x555555555000ULL - 0x10);

	/* basename */
	CHECK_OK("libc.so.6+100", 0x7ffff7dd0000ULL + 0x100);
	/* short prefix - unique module so should succeed */
	CHECK_OK("libc+100", 0x7ffff7dd0000ULL + 0x100);

	/* full path */
	CHECK_OK("/lib/x86_64-linux-gnu/libc.so.6+20",
	    0x7ffff7dd0000ULL + 0x20);

	/* bracketed */
	CHECK_OK("[stack]+8", 0x7ffffffde000ULL + 8);
	CHECK_OK("[stack]-20", 0x7ffffffde000ULL - 0x20);

	/* map:N */
	CHECK_OK("map:1+30", 0x555555555000ULL + 0x30);
	CHECK_OK("map:0", 0x555555554000ULL);

	/* unknown module fails */
	CHECK_FAIL("doesnotexist+10");
	CHECK_FAIL("doesnotexist");

	/* ambiguity: add two modules with basenames starting in
	 * "lib" but different names -> "lib" prefix must be
	 * ambiguous and fail.
	 */
	{
		struct zmap_table amb;
		zmaps_init(&amb);
		add_map(&amb, 0x1000, 0x2000, "r-xp",
		    "/lib/libfoo.so.1");
		add_map(&amb, 0x3000, 0x4000, "r-xp",
		    "/lib/libbar.so.1");
		{
			zaddr_t got = 0;
			int rc = zexpr_eval_maps("lib+10", &regs, &amb, &got);
			if (rc == 0) {
				fprintf(stderr,
				    "FAIL ambiguous 'lib' rc=%d got=%llx\n",
				    rc, (unsigned long long)got);
				failures++;
			}
		}
	}

	/* passing NULL maps falls back to zexpr_eval behaviour */
	{
		zaddr_t got = 0;
		if (zexpr_eval_maps("rip+10", &regs, NULL, &got) != 0 ||
		    got != 0x400010) {
			fprintf(stderr,
			    "FAIL NULL maps fallback got=%llx\n",
			    (unsigned long long)got);
			failures++;
		}
	}

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_expr_maps ok\n");
	return 0;
}
