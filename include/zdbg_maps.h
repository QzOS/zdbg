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

#define ZDBG_MAX_MAPS 1024
#define ZDBG_MAP_NAME_MAX 256

/*
 * Coarse classification of an entry.  Modules are file-image
 * ranges from OS debug events (used for module+offset and PE
 * exports).  Regions are page/protection views from
 * /proc/<pid>/maps or VirtualQueryEx (used for `lm`/`addr`).
 * Linux entries from /proc behave as regions and are also used
 * as modules transparently because their names are file paths.
 */
enum zmap_kind {
	ZMAP_KIND_UNKNOWN = 0,
	ZMAP_KIND_MODULE,
	ZMAP_KIND_REGION
};

/*
 * Backing-store classification for a region.  Mirrors
 * MEMORY_BASIC_INFORMATION.Type on Windows; UNKNOWN elsewhere.
 */
enum zmap_mem_type {
	ZMAP_MEM_UNKNOWN = 0,
	ZMAP_MEM_IMAGE,
	ZMAP_MEM_MAPPED,
	ZMAP_MEM_PRIVATE
};

struct zmap {
	zaddr_t start;
	zaddr_t end;
	zaddr_t offset;
	char perms[5];
	char name[ZDBG_MAP_NAME_MAX];
	/*
	 * Nonzero when (start, end, offset) describe a real file
	 * mapping such that `file_offset = m->offset + (addr -
	 * m->start)` is the raw on-disk byte offset in `name`.
	 * Linux /proc/<pid>/maps entries set this.  Windows
	 * synthetic module maps cover the PE image and are *not*
	 * raw-file-offset valid: PE sections are mapped with gaps
	 * and alignment fixups, so this flag stays 0 and `pw`
	 * rejects them for now.
	 */
	int raw_file_offset_valid;
	enum zmap_kind kind;
	enum zmap_mem_type mem_type;
	/* Raw OS protection/state values where available
	 * (Windows MEMORY_BASIC_INFORMATION.Protect/State).  Zero
	 * elsewhere.  Kept for diagnostics; semantics live in
	 * perms/mem_type. */
	uint32_t protect;
	uint32_t state;
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
 * Refresh *mt with a full memory-region view of the target's
 * address space.  On Windows this enumerates committed regions
 * via VirtualQueryEx.  On Linux this is the same /proc/<pid>/
 * maps view as `zmaps_refresh()`.  Returns 0 on success, -1 if
 * unsupported or on failure.
 */
int zmaps_refresh_regions(struct ztarget *t, struct zmap_table *mt);

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

/*
 * Return a 3-character mnemonic for the region's memory type:
 *   IMG, MAP, PRI, ---.
 */
const char *zmaps_mem_type_str(enum zmap_mem_type mt);

#if defined(_WIN32)
/*
 * Translate a Windows MEMORY_BASIC_INFORMATION.Protect value
 * into the existing 4-char perms representation plus a
 * trailing NUL.  The fourth slot is 'g' for guard pages and
 * 'p' otherwise (private-style, matching /proc maps).  Exposed
 * for unit tests; modifier bits (PAGE_NOCACHE / PAGE_WRITECOMBINE)
 * are ignored.
 */
void zmaps_protect_to_perms(uint32_t protect, char out[5]);
#endif

#endif /* ZDBG_MAPS_H */
