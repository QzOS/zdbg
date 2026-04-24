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

static void
test_find_nearest(struct zsym_table *st)
{
	const struct zsym *s;
	uint64_t off = 0xdead;

	/* exact match: foo at 0x4000a0 */
	s = zsyms_find_nearest(st, 0x4000a0, &off);
	if (s == NULL || strcmp(s->name, "foo") != 0 || off != 0)
		FAILF("nearest exact foo");

	/* inside sized range: sized1 at 0x500000, size 0x20 */
	s = zsyms_find_nearest(st, 0x500010, &off);
	if (s == NULL || strcmp(s->name, "sized1") != 0 || off != 0x10)
		FAILF("nearest inside sized (got %s off %llx)",
		    s ? s->name : "<null>", (unsigned long long)off);

	/* just past sized range should fall through to previous or none */
	s = zsyms_find_nearest(st, 0x500020, &off);
	if (s == NULL || strcmp(s->name, "sized1") != 0 || off != 0x20)
		FAILF("nearest just past sized end (off %llx)",
		    (unsigned long long)off);

	/* no symbol below addr */
	off = 0xdead;
	s = zsyms_find_nearest(st, 0x100, &off);
	if (s != NULL)
		FAILF("nearest below first symbol");

	/* absurd far-away address must be rejected */
	s = zsyms_find_nearest(st, 0x7f0100 + 0x100000, &off);
	if (s != NULL)
		FAILF("nearest accepted absurd far-away offset");

	/* prefer text over data at same address: tie at 0x600000 */
	s = zsyms_find_nearest(st, 0x600000, &off);
	if (s == NULL || s->type != 'T' || strcmp(s->name, "tietext") != 0 ||
	    off != 0)
		FAILF("nearest tie prefers text");
}

static void
test_format_addr(struct zsym_table *st)
{
	char buf[128];
	int n;

	/* unique global name -> just name */
	buf[0] = 'x';
	n = zsyms_format_addr(st, 0x400100, buf, sizeof(buf));
	if (n <= 0 || strcmp(buf, "main") != 0)
		FAILF("format main got '%s'", buf);

	/* offset */
	n = zsyms_format_addr(st, 0x400108, buf, sizeof(buf));
	if (n <= 0 || strcmp(buf, "main+0x8") != 0)
		FAILF("format main+0x8 got '%s'", buf);

	/* ambiguous basename -> module:name */
	n = zsyms_format_addr(st, 0x7f0000, buf, sizeof(buf));
	if (n <= 0 || strcmp(buf, "libc.so.6:dup") != 0)
		FAILF("format ambiguous libc dup got '%s'", buf);

	/* ambiguous with offset */
	n = zsyms_format_addr(st, 0x7f0000 + 4, buf, sizeof(buf));
	if (n <= 0 || strcmp(buf, "libc.so.6:dup+0x4") != 0)
		FAILF("format ambiguous libc dup+4 got '%s'", buf);

	/* unknown address: no symbol, empty string, zero return */
	buf[0] = 'x';
	n = zsyms_format_addr(st, 0x100, buf, sizeof(buf));
	if (n != 0 || buf[0] != 0)
		FAILF("format unknown addr n=%d '%s'", n, buf);
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

	/* sized symbol for nearest-inside tests */
	{
		struct zsym *s = &st.syms[st.count++];
		memset(s, 0, sizeof(*s));
		s->addr = 0x500000;
		s->size = 0x20;
		s->type = 'T';
		s->bind = 'G';
		strncpy(s->name, "sized1", ZDBG_SYM_NAME_MAX - 1);
		strncpy(s->module, "/home/me/build/examples/testprog",
		    ZDBG_SYM_MODULE_MAX - 1);
	}
	/* tie at 0x600000: text + data, text should win */
	add_sym(&st, 0x600000, 'D', "tiedata",
	    "/home/me/build/examples/testprog");
	add_sym(&st, 0x600000, 'T', "tietext",
	    "/home/me/build/examples/testprog");

	test_find_exact(&st);
	test_find_qualified(&st);
	test_resolve(&st);
	test_expr(&st, &mt);
	test_find_nearest(&st);
	test_format_addr(&st);

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_symbols ok\n");
	return 0;
}
