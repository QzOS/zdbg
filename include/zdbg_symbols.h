/*
 * zdbg_symbols.h - fixed-size ELF symbol table.
 *
 * The symbol table is populated from ELF64 .symtab / .dynsym
 * sections of file-backed executable mappings reported by the
 * OS.  This is not DWARF and has nothing to do with source
 * lines, types or locals.
 *
 * Runtime addresses are computed from the module load bias
 * derived from /proc/<pid>/maps:
 *
 *     load_bias    = mapping.start - mapping.offset
 *     runtime_addr = load_bias + st_value
 *
 * For ET_EXEC binaries this formula still yields the st_value
 * itself when mapping.offset matches the file layout; if not,
 * the ELF loader falls back to using st_value as-is.
 */

#ifndef ZDBG_SYMBOLS_H
#define ZDBG_SYMBOLS_H

#include "zdbg.h"
#include "zdbg_target.h"
#include "zdbg_maps.h"

#define ZDBG_MAX_SYMBOLS   4096
#define ZDBG_SYM_NAME_MAX  256
#define ZDBG_SYM_MODULE_MAX 256

struct zsym {
	zaddr_t  addr;
	uint64_t size;
	char     type;		/* 'T','t','D','d','?' */
	char     bind;		/* 'G'lobal, 'L'ocal, 'W'eak */
	char     name[ZDBG_SYM_NAME_MAX];
	char     module[ZDBG_SYM_MODULE_MAX];
};

struct zsym_table {
	struct zsym syms[ZDBG_MAX_SYMBOLS];
	int count;
	int truncated;
};

void zsyms_init(struct zsym_table *st);
void zsyms_clear(struct zsym_table *st);

/*
 * Refresh symbols for every file-backed module currently in
 * *maps.  Duplicate pathnames are processed once.  Returns the
 * number of modules successfully scanned (>= 0) or -1 on fatal
 * argument error.  A zero return is not an error: some targets
 * are fully stripped.
 */
int zsyms_refresh(struct ztarget *t, const struct zmap_table *maps,
    struct zsym_table *st);

/*
 * Print the whole table, optionally filtered.  If filter is
 * non-NULL and non-empty, only rows whose name or module
 * basename contains filter (case sensitive substring) are
 * printed.  A "module:name" filter is also supported; the
 * module part must match the module basename.
 */
void zsyms_print(const struct zsym_table *st, const char *filter);

/*
 * Look up a symbol by exact name across all modules.  If
 * *ambiguous is non-NULL it is set to 1 on multiple matches.
 * Exact-duplicate rows (same module+addr+name) coalesce and do
 * not trigger ambiguity.
 */
const struct zsym *zsyms_find_exact(const struct zsym_table *st,
    const char *name, int *ambiguous);

/*
 * Look up a symbol restricted to a named module.  Module
 * matching is delegated to zmaps_find_module() semantics
 * (basename, prefix, full path).  Pass NULL maps to match by
 * basename substring against the stored module field only.
 */
const struct zsym *zsyms_find_qualified(const struct zsym_table *st,
    const struct zmap_table *maps, const char *module,
    const char *name, int *ambiguous);

/*
 * Resolve a symbol expression of the form
 *   name
 *   module:name
 * into *out.  This helper does not handle +/- offsets; that is
 * done by the expression evaluator.  Returns 0 on success,
 * -1 on unknown, -2 on ambiguity.
 */
int zsyms_resolve(const struct zsym_table *st,
    const struct zmap_table *maps, const char *expr, zaddr_t *out);

#endif /* ZDBG_SYMBOLS_H */
