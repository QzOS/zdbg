/*
 * test_symbols.c - symbol-table lookup and symbol-aware
 * expression evaluation tests.  Populates a zsym_table directly
 * without any real ELF files.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_symbols.h"
#include "zdbg_expr.h"
#include "zdbg_maps.h"
#include "zdbg_regs.h"

static int failures;

#define FAILF(...) do {                                               \
	fprintf(stderr, "FAIL %s:%d ", __FILE__, __LINE__);           \
	fprintf(stderr, __VA_ARGS__);                                 \
	fprintf(stderr, "\n");                                        \
	failures++;                                                   \
} while (0)

static void
add_sym(struct zsym_table *st, zaddr_t addr, char type,
    const char *name, const char *module)
{
	struct zsym *s = &st->syms[st->count++];
	memset(s, 0, sizeof(*s));
	s->addr = addr;
	s->type = type;
	s->bind = (type >= 'A' && type <= 'Z') ? 'G' : 'L';
	strncpy(s->name, name, ZDBG_SYM_NAME_MAX - 1);
	strncpy(s->module, module, ZDBG_SYM_MODULE_MAX - 1);
}

static void
add_map(struct zmap_table *mt, zaddr_t start, zaddr_t end,
    const char *perms, const char *name)
{
	struct zmap *m = &mt->maps[mt->count++];
	memset(m, 0, sizeof(*m));
	m->start = start;
	m->end = end;
	strncpy(m->perms, perms, 4);
	m->perms[4] = 0;
	strncpy(m->name, name, ZDBG_MAP_NAME_MAX - 1);
}

static void
test_find_exact(struct zsym_table *st)
{
	int amb = 0;
	const struct zsym *s;

	s = zsyms_find_exact(st, "main", &amb);
	if (s == NULL || s->addr != 0x400100 || amb != 0)
		FAILF("find main");

	s = zsyms_find_exact(st, "foo", &amb);
	if (s == NULL || s->addr != 0x4000a0)
		FAILF("find foo");

	/* unknown symbol */
	amb = 0;
	s = zsyms_find_exact(st, "nosuch", &amb);
	if (s != NULL || amb != 0)
		FAILF("nosuch");

	/* ambiguous unqualified */
	amb = 0;
	s = zsyms_find_exact(st, "dup", &amb);
	if (s != NULL || amb != 1)
		FAILF("ambiguous dup");
}

static void
test_find_qualified(struct zsym_table *st)
{
	int amb = 0;
	const struct zsym *s;

	s = zsyms_find_qualified(st, NULL, "testprog", "main", &amb);
	if (s == NULL || s->addr != 0x400100)
		FAILF("qualified main");

	s = zsyms_find_qualified(st, NULL, "libc", "dup", &amb);
	if (s == NULL || s->addr != 0x7f0000)
		FAILF("qualified libc:dup");

	s = zsyms_find_qualified(st, NULL, "testprog", "dup", &amb);
	if (s == NULL || s->addr != 0x400200)
		FAILF("qualified testprog:dup");

	s = zsyms_find_qualified(st, NULL, "nosuch", "main", &amb);
	if (s != NULL)
		FAILF("qualified nosuch:main should fail");

	s = zsyms_find_qualified(st, NULL, "testprog", "nosuch", &amb);
	if (s != NULL)
		FAILF("qualified testprog:nosuch should fail");
}

static void
test_resolve(struct zsym_table *st)
{
	zaddr_t out = 0;

	if (zsyms_resolve(st, NULL, "main", &out) != 0 || out != 0x400100)
		FAILF("resolve main");

	if (zsyms_resolve(st, NULL, "testprog:main", &out) != 0 ||
	    out != 0x400100)
		FAILF("resolve testprog:main");

	if (zsyms_resolve(st, NULL, "nosuch", &out) != -1)
		FAILF("resolve nosuch");

	if (zsyms_resolve(st, NULL, "dup", &out) != -2)
		FAILF("resolve dup should be ambiguous");
}

static void
test_expr(struct zsym_table *st, struct zmap_table *mt)
{
	struct zregs regs;
	zaddr_t out = 0;

	zregs_clear(&regs);
	regs.rip = 0x401000;

	/* numeric still works */
	if (zexpr_eval_symbols("401000", &regs, mt, st, &out) != 0 ||
	    out != 0x401000)
		FAILF("expr numeric");

	/* register still works */
	if (zexpr_eval_symbols("rip+10", &regs, mt, st, &out) != 0 ||
	    out != 0x401010)
		FAILF("expr rip+10");

	/* exact symbol */
	if (zexpr_eval_symbols("main", &regs, mt, st, &out) != 0 ||
	    out != 0x400100)
		FAILF("expr main");

	/* "main+10": "main" is also a module name; map-relative
	 * semantics win here (preserving PR #8 behaviour). */
	if (zexpr_eval_symbols("main+10", &regs, mt, st, &out) != 0 ||
	    out != 0x400010)
		FAILF("expr main+10 map-relative (got %llx)",
		    (unsigned long long)out);

	/* main+1000 keeps mapping-relative semantics */
	if (zexpr_eval_symbols("main+1000", &regs, mt, st, &out) != 0 ||
	    out != 0x400000 + 0x1000)
		FAILF("expr main+1000 map-relative (got %llx)",
		    (unsigned long long)out);

	/* qualified module:symbol */
	if (zexpr_eval_symbols("libc:dup", &regs, mt, st, &out) != 0 ||
	    out != 0x7f0000)
		FAILF("expr libc:dup");

	/* qualified with offset */
	if (zexpr_eval_symbols("libc:dup+4", &regs, mt, st, &out) != 0 ||
	    out != 0x7f0004)
		FAILF("expr libc:dup+4");

	/* symbol-offset */
	if (zexpr_eval_symbols("foo-4", &regs, mt, st, &out) != 0 ||
	    out != 0x4000a0 - 4)
		FAILF("expr foo-4");

	/* symbol+offset (foo is not a module name -> symbol wins) */
	if (zexpr_eval_symbols("foo+4", &regs, mt, st, &out) != 0 ||
	    out != 0x4000a0 + 4)
		FAILF("expr foo+4");

	/* ambiguous unqualified should fail */
	if (zexpr_eval_symbols("dup", &regs, mt, st, &out) == 0)
		FAILF("expr dup should be ambiguous");

	/* unknown symbol fails */
	if (zexpr_eval_symbols("nosuch", &regs, mt, st, &out) == 0)
		FAILF("expr nosuch should fail");

	/* NULL syms -> legacy behaviour still works */
	if (zexpr_eval_symbols("401000", &regs, mt, NULL, &out) != 0 ||
	    out != 0x401000)
		FAILF("NULL syms numeric");
}

int
main(void)
{
	struct zsym_table st;
	struct zmap_table mt;

	zsyms_init(&st);
	zmaps_init(&mt);

	add_map(&mt, 0x400000, 0x402000, "r-xp",
	    "/home/me/build/examples/testprog");
	add_map(&mt, 0x700000, 0x800000, "r-xp",
	    "/lib/x86_64-linux-gnu/libc.so.6");
	zmaps_set_main_hint(&mt, "/home/me/build/examples/testprog");

	add_sym(&st, 0x4000a0, 't', "foo",
	    "/home/me/build/examples/testprog");
	add_sym(&st, 0x400100, 'T', "main",
	    "/home/me/build/examples/testprog");
	add_sym(&st, 0x400200, 'T', "dup",
	    "/home/me/build/examples/testprog");
	add_sym(&st, 0x7f0000, 'T', "dup",
	    "/lib/x86_64-linux-gnu/libc.so.6");
	add_sym(&st, 0x7f0100, 'T', "malloc",
	    "/lib/x86_64-linux-gnu/libc.so.6");

	test_find_exact(&st);
	test_find_qualified(&st);
	test_resolve(&st);
	test_expr(&st, &mt);

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_symbols ok\n");
	return 0;
}
