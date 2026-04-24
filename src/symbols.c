/*
 * symbols.c - host-independent ELF symbol table helpers.
 *
 * The heavy lifting of parsing ELF64 files lives in
 * src/os_linux/symbols_elf.c.  This file provides the shared
 * table management, printing, and name resolution logic plus
 * the non-Linux fallback for zsyms_refresh().
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "zdbg_symbols.h"
#include "zdbg_maps.h"

static const char *
basename_of(const char *path)
{
	const char *p;
	const char *last = path;

	if (path == NULL)
		return "";
	for (p = path; *p; p++)
		if (*p == '/' || *p == '\\')
			last = p + 1;
	return last;
}

void
zsyms_init(struct zsym_table *st)
{
	if (st == NULL)
		return;
	memset(st, 0, sizeof(*st));
}

void
zsyms_clear(struct zsym_table *st)
{
	if (st == NULL)
		return;
	st->count = 0;
	st->truncated = 0;
}

/*
 * Split "module:name" into module/name.  Returns 1 if colon
 * present, 0 otherwise.  mod/nm buffers must be at least
 * ZDBG_SYM_MODULE_MAX and ZDBG_SYM_NAME_MAX bytes.
 */
static int
split_qualified(const char *expr, char *mod, char *nm)
{
	const char *colon = strchr(expr, ':');
	size_t m;
	size_t n;

	if (colon == NULL) {
		n = strlen(expr);
		if (n >= ZDBG_SYM_NAME_MAX)
			n = ZDBG_SYM_NAME_MAX - 1;
		memcpy(nm, expr, n);
		nm[n] = 0;
		mod[0] = 0;
		return 0;
	}
	m = (size_t)(colon - expr);
	if (m >= ZDBG_SYM_MODULE_MAX)
		m = ZDBG_SYM_MODULE_MAX - 1;
	memcpy(mod, expr, m);
	mod[m] = 0;
	n = strlen(colon + 1);
	if (n >= ZDBG_SYM_NAME_MAX)
		n = ZDBG_SYM_NAME_MAX - 1;
	memcpy(nm, colon + 1, n);
	nm[n] = 0;
	return 1;
}

void
zsyms_print(const struct zsym_table *st, const char *filter)
{
	char fmod[ZDBG_SYM_MODULE_MAX];
	char fname[ZDBG_SYM_NAME_MAX];
	int qualified = 0;
	int printed = 0;
	int i;

	if (st == NULL)
		return;

	if (filter != NULL && *filter != 0)
		qualified = split_qualified(filter, fmod, fname);

	for (i = 0; i < st->count; i++) {
		const struct zsym *s = &st->syms[i];
		if (filter != NULL && *filter != 0) {
			if (qualified) {
				const char *mb = basename_of(s->module);
				if (fmod[0] != 0 && strstr(mb, fmod) == NULL)
					continue;
				if (fname[0] != 0 &&
				    strstr(s->name, fname) == NULL)
					continue;
			} else {
				const char *mb = basename_of(s->module);
				if (strstr(s->name, fname) == NULL &&
				    strstr(mb, fname) == NULL)
					continue;
			}
		}
		printf("%016llx %c %s %s\n",
		    (unsigned long long)s->addr, s->type, s->name,
		    s->module);
		printed++;
	}
	if (st->truncated)
		printf("(symbol table truncated at %d symbols)\n",
		    ZDBG_MAX_SYMBOLS);
	if (printed == 0 && filter != NULL && *filter != 0)
		printf("no symbols match '%s'\n", filter);
}

const struct zsym *
zsyms_find_exact(const struct zsym_table *st, const char *name,
    int *ambiguous)
{
	const struct zsym *hit = NULL;
	int i;

	if (ambiguous != NULL)
		*ambiguous = 0;
	if (st == NULL || name == NULL || *name == 0)
		return NULL;

	for (i = 0; i < st->count; i++) {
		const struct zsym *s = &st->syms[i];
		if (strcmp(s->name, name) != 0)
			continue;
		if (hit == NULL) {
			hit = s;
			continue;
		}
		/* coalesce exact duplicates (same module + addr) */
		if (hit->addr == s->addr &&
		    strcmp(hit->module, s->module) == 0)
			continue;
		if (ambiguous != NULL)
			*ambiguous = 1;
		return NULL;
	}
	return hit;
}

/*
 * Decide if a symbol row's module is considered to belong to
 * the named module.  Selection uses the same spirit as
 * zmaps_find_module(): prefer an exact pathname/basename match,
 * accept a prefix match ("libc" matching "libc.so.6").
 */
/*
 * Case-insensitive name comparison on Windows, case-sensitive
 * elsewhere.  Module names on Windows are case-insensitive
 * (KERNEL32.DLL == kernel32.dll).
 */
static int
name_eq(const char *a, const char *b)
{
#if defined(_WIN32)
	while (*a && *b) {
		int ca = (unsigned char)*a;
		int cb = (unsigned char)*b;
		if (ca >= 'A' && ca <= 'Z') ca += 'a' - 'A';
		if (cb >= 'A' && cb <= 'Z') cb += 'a' - 'A';
		if (ca != cb)
			return 0;
		a++; b++;
	}
	return *a == 0 && *b == 0;
#else
	return strcmp(a, b) == 0;
#endif
}

static int
name_neq(const char *a, const char *b, size_t n)
{
#if defined(_WIN32)
	size_t i;
	for (i = 0; i < n; i++) {
		int ca = (unsigned char)a[i];
		int cb = (unsigned char)b[i];
		if (ca >= 'A' && ca <= 'Z') ca += 'a' - 'A';
		if (cb >= 'A' && cb <= 'Z') cb += 'a' - 'A';
		if (ca != cb)
			return 1;
		if (ca == 0)
			return 0;
	}
	return 0;
#else
	return strncmp(a, b, n) != 0;
#endif
}

static int
module_matches(const char *sym_module, const char *query)
{
	const char *b;
	size_t qn;

	if (sym_module == NULL || query == NULL || *query == 0)
		return 0;
	if (name_eq(sym_module, query))
		return 1;
	b = basename_of(sym_module);
	if (name_eq(b, query))
		return 1;
	qn = strlen(query);
	if (qn == 0 || name_neq(b, query, qn))
		return 0;
	{
		char sep = b[qn];
		if (sep == 0 || sep == '.' || sep == '-' || sep == '_')
			return 1;
	}
	return 0;
}

const struct zsym *
zsyms_find_qualified(const struct zsym_table *st,
    const struct zmap_table *maps, const char *module,
    const char *name, int *ambiguous)
{
	const struct zmap *mm = NULL;
	const struct zsym *hit = NULL;
	int i;

	if (ambiguous != NULL)
		*ambiguous = 0;
	if (st == NULL || module == NULL || *module == 0 ||
	    name == NULL || *name == 0)
		return NULL;

	if (maps != NULL) {
		int mam = 0;
		mm = zmaps_find_module(maps, module, &mam);
		if (mm == NULL && mam) {
			if (ambiguous != NULL)
				*ambiguous = 1;
			return NULL;
		}
	}

	for (i = 0; i < st->count; i++) {
		const struct zsym *s = &st->syms[i];
		int match;

		if (strcmp(s->name, name) != 0)
			continue;
		if (mm != NULL)
			match = name_eq(s->module, mm->name);
		else
			match = module_matches(s->module, module);
		if (!match)
			continue;

		if (hit == NULL) {
			hit = s;
			continue;
		}
		if (hit->addr == s->addr &&
		    strcmp(hit->module, s->module) == 0)
			continue;
		if (ambiguous != NULL)
			*ambiguous = 1;
		return NULL;
	}
	return hit;
}

int
zsyms_resolve(const struct zsym_table *st, const struct zmap_table *maps,
    const char *expr, zaddr_t *out)
{
	char mod[ZDBG_SYM_MODULE_MAX];
	char nm[ZDBG_SYM_NAME_MAX];
	const struct zsym *s;
	int amb = 0;

	if (st == NULL || expr == NULL || *expr == 0 || out == NULL)
		return -1;

	if (split_qualified(expr, mod, nm)) {
		if (nm[0] == 0)
			return -1;
		s = zsyms_find_qualified(st, maps, mod, nm, &amb);
	} else {
		s = zsyms_find_exact(st, nm, &amb);
	}
	if (s != NULL) {
		*out = s->addr;
		return 0;
	}
	return amb ? -2 : -1;
}

/*
 * Rank a symbol type for tie-breaking when multiple symbols sit
 * at the same address.  Higher is better.  Text symbols win over
 * data; data wins over unknown.  Unknown defaults to zero.
 */
static int
type_rank(char t)
{
	switch (t) {
	case 'T':
	case 't':
		return 3;
	case 'D':
	case 'd':
		return 2;
	case '?':
		return 0;
	default:
		return 1;
	}
}

/*
 * Return 1 if candidate a is a better "nearest" match for addr
 * than candidate b, 0 otherwise.  Comparisons assume both a and
 * b have a->addr <= addr and b->addr <= addr already.
 */
static int
nearest_better(const struct zsym *a, const struct zsym *b, zaddr_t addr)
{
	int ar;
	int br;

	if (b == NULL)
		return 1;
	if (a->addr != b->addr)
		return a->addr > b->addr;
	/* same address: prefer the one whose sized range contains addr */
	{
		int a_in = (a->size != 0 && addr < a->addr + a->size);
		int b_in = (b->size != 0 && addr < b->addr + b->size);
		if (a_in != b_in)
			return a_in;
	}
	ar = type_rank(a->type);
	br = type_rank(b->type);
	if (ar != br)
		return ar > br;
	if (a->bind != b->bind) {
		if (a->bind == 'G' && b->bind != 'G')
			return 1;
		if (b->bind == 'G' && a->bind != 'G')
			return 0;
	}
	/* deterministic fallback: prefer lexicographically smaller name */
	return strcmp(a->name, b->name) < 0;
}

const struct zsym *
zsyms_find_nearest(const struct zsym_table *st, zaddr_t addr,
    uint64_t *offp)
{
	const struct zsym *best = NULL;
	uint64_t off;
	int i;

	if (offp != NULL)
		*offp = 0;
	if (st == NULL)
		return NULL;

	for (i = 0; i < st->count; i++) {
		const struct zsym *s = &st->syms[i];
		if (s->addr > addr)
			continue;
		if (nearest_better(s, best, addr))
			best = s;
	}
	if (best == NULL)
		return NULL;

	off = (uint64_t)(addr - best->addr);
	/* accept inside sized range */
	if (best->size != 0 && off < best->size) {
		if (offp != NULL)
			*offp = off;
		return best;
	}
	/* accept small offsets outside range / for sizeless syms */
	if (off <= ZDBG_NEAREST_MAX_OFF) {
		if (offp != NULL)
			*offp = off;
		return best;
	}
	return NULL;
}

/*
 * Decide whether a symbol name is unique across modules in st.
 * Duplicate rows that differ only by type/bind but share name +
 * module are treated as the same symbol and do not cause
 * ambiguity.
 */
static int
name_is_unique(const struct zsym_table *st, const struct zsym *target)
{
	int seen_other = 0;
	int i;

	if (st == NULL || target == NULL)
		return 0;
	for (i = 0; i < st->count; i++) {
		const struct zsym *s = &st->syms[i];
		if (s == target)
			continue;
		if (strcmp(s->name, target->name) != 0)
			continue;
		if (strcmp(s->module, target->module) == 0)
			continue;
		seen_other = 1;
		break;
	}
	return !seen_other;
}

int
zsyms_format_addr(const struct zsym_table *st, zaddr_t addr,
    char *buf, size_t buflen)
{
	const struct zsym *s;
	uint64_t off = 0;
	const char *mod;
	int n;

	if (buf != NULL && buflen > 0)
		buf[0] = 0;
	if (st == NULL || buf == NULL || buflen == 0)
		return 0;

	s = zsyms_find_nearest(st, addr, &off);
	if (s == NULL)
		return 0;

	mod = basename_of(s->module);
	if (name_is_unique(st, s)) {
		if (off == 0)
			n = snprintf(buf, buflen, "%s", s->name);
		else
			n = snprintf(buf, buflen, "%s+0x%llx", s->name,
			    (unsigned long long)off);
	} else {
		if (off == 0)
			n = snprintf(buf, buflen, "%s:%s", mod, s->name);
		else
			n = snprintf(buf, buflen, "%s:%s+0x%llx", mod,
			    s->name, (unsigned long long)off);
	}
	if (n < 0)
		return 0;
	if ((size_t)n >= buflen)
		return (int)(buflen - 1);
	return n;
}

#if defined(_WIN32)
int
zsyms_refresh(struct ztarget *t, const struct zmap_table *maps,
    struct zsym_table *st)
{
	(void)maps;
	if (st == NULL)
		return -1;
	zsyms_clear(st);
	return ztarget_windows_fill_syms(t, st);
}
#elif !defined(__linux__)
int
zsyms_refresh(struct ztarget *t, const struct zmap_table *maps,
    struct zsym_table *st)
{
	(void)t;
	(void)maps;
	if (st != NULL)
		zsyms_clear(st);
	return 0;
}
#endif
