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
		if (*p == '/')
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
static int
module_matches(const char *sym_module, const char *query)
{
	const char *b;
	size_t qn;

	if (sym_module == NULL || query == NULL || *query == 0)
		return 0;
	if (strcmp(sym_module, query) == 0)
		return 1;
	b = basename_of(sym_module);
	if (strcmp(b, query) == 0)
		return 1;
	qn = strlen(query);
	if (qn == 0 || strncmp(b, query, qn) != 0)
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
			match = (strcmp(s->module, mm->name) == 0);
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

#if !defined(__linux__)
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
