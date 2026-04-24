/*
 * zdbg_patch.h - patch journal.
 *
 * The patch subsystem records user-initiated memory mutations
 * (`e`, `f`, `a`, `pa`, `ij`) so they can be listed, reverted,
 * reapplied, saved to disk as raw bytes or a simple textual
 * patch script, and, when the address is backed by a real file
 * mapping, explicitly written back to that file via `pw`.
 *
 * Software-breakpoint memory writes are *not* patches and
 * intentionally do not go through this journal.
 */

#ifndef ZDBG_PATCH_H
#define ZDBG_PATCH_H

#include "zdbg.h"
#include "zdbg_maps.h"

#define ZDBG_MAX_PATCHES        256
#define ZDBG_PATCH_MAX_BYTES    256
#define ZDBG_PATCH_ORIGIN_MAX   16
#define ZDBG_PATCH_FILE_MAX     ZDBG_MAP_NAME_MAX

enum zpatch_state {
	ZPATCH_EMPTY = 0,
	ZPATCH_APPLIED,
	ZPATCH_REVERTED
};

struct zpatch {
	enum zpatch_state state;
	zaddr_t addr;
	size_t len;
	uint8_t old_bytes[ZDBG_PATCH_MAX_BYTES];
	uint8_t new_bytes[ZDBG_PATCH_MAX_BYTES];
	char origin[ZDBG_PATCH_ORIGIN_MAX];

	int has_file;
	char file[ZDBG_PATCH_FILE_MAX];
	uint64_t file_off;

	/*
	 * Optional PE-image RVA, valid when has_rva != 0.  Set
	 * for Windows PE-backed patches so `pf` can show both the
	 * RVA and the raw file offset.  Linux raw-file mappings
	 * leave has_rva == 0.
	 */
	int has_rva;
	uint64_t rva;
};

struct zpatch_table {
	struct zpatch patches[ZDBG_MAX_PATCHES];
	int next_id_hint;
};

void zpatch_table_init(struct zpatch_table *pt);

/*
 * Record a new patch.  Copies both old and new bytes into the
 * entry.  Returns the patch id on success, -1 if the journal is
 * full, -2 if len is 0 or exceeds ZDBG_PATCH_MAX_BYTES.
 */
int  zpatch_record(struct zpatch_table *pt, zaddr_t addr,
    const void *old_bytes, const void *new_bytes, size_t len,
    const char *origin);

/*
 * Fetch a patch by id.  Returns 0 on success with *out set,
 * -1 if the id is out of range or the slot is empty.
 */
int  zpatch_get(const struct zpatch_table *pt, int id,
    const struct zpatch **out);

/* Mark the patch in state ZPATCH_APPLIED as reverted. */
int  zpatch_mark_reverted(struct zpatch_table *pt, int id);

/* Mark the patch in state ZPATCH_REVERTED as applied. */
int  zpatch_mark_applied(struct zpatch_table *pt, int id);

/*
 * Check whether a new range [addr, addr+len) overlaps any
 * currently-applied patch in *pt.  Returns the id of the first
 * overlap found, or -1 if none.  Used only for a warning.
 */
int  zpatch_find_overlap(const struct zpatch_table *pt,
    zaddr_t addr, size_t len);

/*
 * Resolve a virtual address range to an on-disk file mapping.
 *
 * Succeeds only when [addr, addr+len) sits wholly inside one
 * file-backed mapping whose name is not bracketed ("[heap]",
 * "[vdso]", ...) and not flagged " (deleted)".
 *
 * On success returns 0, writes the mapping pathname into
 * file[0..filecap-1] and the file offset into *offp.  Returns
 * -1 otherwise.  maps may be NULL.
 */
int  zpatch_va_to_file(const struct zmap_table *maps, zaddr_t addr,
    size_t len, char *file, size_t filecap, uint64_t *offp);

/*
 * Extended VA-to-file resolver.
 *
 * Behaves like zpatch_va_to_file() for raw-file-offset-valid
 * mappings (Linux /proc/<pid>/maps).  For maps whose name is a
 * PE file path but raw_file_offset_valid == 0 (Windows synthetic
 * image maps) the function parses the PE32+ file on disk and
 * translates rva = addr - map.start to a raw file offset.  It
 * succeeds only when the whole [addr, addr+len) lies inside one
 * PE section's raw-backed range.
 *
 * If rvap != NULL it receives the PE RVA on success when the
 * resolution went through the PE path (otherwise *rvap is left
 * unchanged).  Callers can detect the PE path by passing a
 * sentinel value.
 *
 * Returns 0 on success, -1 otherwise.
 */
int  zpatch_va_to_file_ex(const struct zmap_table *maps, zaddr_t addr,
    size_t len, char *file, size_t filecap, uint64_t *offp,
    uint64_t *rvap, int *via_pe);

/*
 * Populate p->has_file/p->file/p->file_off from *maps if the
 * patch address is file-backed.  Returns 0 on success, -1 if
 * no file mapping was found (has_file is cleared in that case).
 */
int  zpatch_resolve_file(struct zpatch *p, const struct zmap_table *maps);

#endif /* ZDBG_PATCH_H */
