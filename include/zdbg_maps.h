/*
 * zdbg_maps.h - memory-map / module table.
 *
 * A "module" in zdbg is deliberately simple: a named mapping
 * reported by the OS for a process.  On Linux we read
 * /proc/<pid>/maps.  On other hosts the table stays empty.
 *
 * Module-relative expressions like `main+offset` or
 * `libc+offset` resolve against the start of a selected mapping.
 * This is mapping-relative, not ELF image-base relative.
 */

#ifndef ZDBG_MAPS_H
#define ZDBG_MAPS_H

#include "zdbg.h"
#include "zdbg_target.h"

#define ZDBG_MAX_MAPS 256
#define ZDBG_MAP_NAME_MAX 256

struct zmap {
	zaddr_t start;
	zaddr_t end;
	zaddr_t offset;
	char perms[5];
	char name[ZDBG_MAP_NAME_MAX];
};

struct zmap_table {
	struct zmap maps[ZDBG_MAX_MAPS];
	int count;
	int truncated;
	char main_hint[ZDBG_MAP_NAME_MAX];
};

void zmaps_init(struct zmap_table *mt);

/*
 * Parse one /proc/<pid>/maps style line into *m.  Returns 0 on
 * success, -1 on malformed input.  The line may or may not end
 * in '\n'; trailing newline is stripped from the name.  Useful
 * for unit tests that want to avoid a live /proc.
 */
int zmaps_parse_line(const char *line, struct zmap *m);

/*
 * Refresh the table from the running target (Linux only).
 * Returns 0 on success, -1 on failure.
 */
int zmaps_refresh(struct ztarget *t, struct zmap_table *mt);

/*
 * Record a hint for resolving the `main` pseudo-module.  This is
 * usually the path the debugger launched.  Safe to call with
 * NULL to clear.
 */
void zmaps_set_main_hint(struct zmap_table *mt, const char *path);

void zmaps_print(const struct zmap_table *mt);
void zmaps_print_one(int idx, const struct zmap *m);

const struct zmap *zmaps_find_by_addr(const struct zmap_table *mt,
    zaddr_t addr);

/*
 * Look up a module by name.  Accepts:
 *   - "main"                 -> best main-executable mapping
 *   - absolute path          -> exact pathname match
 *   - basename               -> exact basename match
 *   - short prefix           -> unique prefix of basename
 *   - bracketed "[stack]"    -> exact special-map name
 *   - "map:N"                -> the Nth mapping
 *
 * Returns NULL on no match or ambiguity.  If *ambiguous is
 * non-NULL it is set to 1 when more than one module matched.
 */
const struct zmap *zmaps_find_module(const struct zmap_table *mt,
    const char *name, int *ambiguous);

/*
 * Resolve `name` + `off` into *out.  Returns:
 *   0  success
 *  -1  unknown module
 *  -2  ambiguous module name
 */
int zmaps_resolve(const struct zmap_table *mt, const char *name,
    zaddr_t off, zaddr_t *out);

#endif /* ZDBG_MAPS_H */
