/*
 * patch.c - patch journal implementation.
 *
 * A fixed-size table of user memory patches.  Recording is
 * cheap: copy old/new bytes into the first empty slot.  There
 * is no dynamic allocation, no blob storage, no ELF awareness.
 *
 * VA-to-file resolution uses the existing /proc/<pid>/maps
 * table.  The rule is intentionally narrow (see zdbg_patch.h):
 * whole range must be inside exactly one file-backed mapping
 * whose name is neither bracketed nor flagged " (deleted)".
 */

#include <stdio.h>
#include <string.h>

#include "zdbg.h"
#include "zdbg_patch.h"
#include "zdbg_maps.h"
#include "zdbg_pe.h"

void
zpatch_table_init(struct zpatch_table *pt)
{
	if (pt == NULL)
		return;
	memset(pt, 0, sizeof(*pt));
	pt->next_id_hint = 0;
}

static int
alloc_slot(struct zpatch_table *pt)
{
	int i;
	int start;

	if (pt == NULL)
		return -1;
	start = pt->next_id_hint;
	if (start < 0 || start >= ZDBG_MAX_PATCHES)
		start = 0;
	for (i = 0; i < ZDBG_MAX_PATCHES; i++) {
		int id = (start + i) % ZDBG_MAX_PATCHES;
		if (pt->patches[id].state == ZPATCH_EMPTY) {
			pt->next_id_hint = (id + 1) % ZDBG_MAX_PATCHES;
			return id;
		}
	}
	return -1;
}

int
zpatch_record(struct zpatch_table *pt, zaddr_t addr,
    const void *old_bytes, const void *new_bytes, size_t len,
    const char *origin)
{
	int id;
	struct zpatch *p;

	if (pt == NULL || old_bytes == NULL || new_bytes == NULL)
		return -1;
	if (len == 0 || len > ZDBG_PATCH_MAX_BYTES)
		return -2;

	id = alloc_slot(pt);
	if (id < 0)
		return -1;

	p = &pt->patches[id];
	memset(p, 0, sizeof(*p));
	p->state = ZPATCH_APPLIED;
	p->addr = addr;
	p->len = len;
	memcpy(p->old_bytes, old_bytes, len);
	memcpy(p->new_bytes, new_bytes, len);
	if (origin != NULL) {
		size_t n = strlen(origin);
		if (n >= sizeof(p->origin))
			n = sizeof(p->origin) - 1;
		memcpy(p->origin, origin, n);
		p->origin[n] = 0;
	}
	p->has_file = 0;
	p->file[0] = 0;
	p->file_off = 0;
	p->has_rva = 0;
	p->rva = 0;
	return id;
}

int
zpatch_get(const struct zpatch_table *pt, int id, const struct zpatch **out)
{
	if (pt == NULL || out == NULL)
		return -1;
	if (id < 0 || id >= ZDBG_MAX_PATCHES)
		return -1;
	if (pt->patches[id].state == ZPATCH_EMPTY)
		return -1;
	*out = &pt->patches[id];
	return 0;
}

int
zpatch_mark_reverted(struct zpatch_table *pt, int id)
{
	if (pt == NULL)
		return -1;
	if (id < 0 || id >= ZDBG_MAX_PATCHES)
		return -1;
	if (pt->patches[id].state != ZPATCH_APPLIED)
		return -1;
	pt->patches[id].state = ZPATCH_REVERTED;
	return 0;
}

int
zpatch_mark_applied(struct zpatch_table *pt, int id)
{
	if (pt == NULL)
		return -1;
	if (id < 0 || id >= ZDBG_MAX_PATCHES)
		return -1;
	if (pt->patches[id].state != ZPATCH_REVERTED)
		return -1;
	pt->patches[id].state = ZPATCH_APPLIED;
	return 0;
}

static int
ranges_overlap(zaddr_t a, size_t alen, zaddr_t b, size_t blen)
{
	zaddr_t ae = a + (zaddr_t)alen;
	zaddr_t be = b + (zaddr_t)blen;
	if (ae <= b)
		return 0;
	if (be <= a)
		return 0;
	return 1;
}

int
zpatch_find_overlap(const struct zpatch_table *pt, zaddr_t addr, size_t len)
{
	int i;

	if (pt == NULL || len == 0)
		return -1;
	for (i = 0; i < ZDBG_MAX_PATCHES; i++) {
		const struct zpatch *q = &pt->patches[i];
		if (q->state != ZPATCH_APPLIED)
			continue;
		if (ranges_overlap(addr, len, q->addr, q->len))
			return i;
	}
	return -1;
}

static int
is_bracketed(const char *name)
{
	size_t n;

	if (name == NULL || name[0] != '[')
		return 0;
	n = strlen(name);
	return n > 0 && name[n - 1] == ']';
}

static int
is_deleted_mapping(const char *name)
{
	size_t n;
	const char *suffix = " (deleted)";
	size_t sl = strlen(suffix);

	if (name == NULL)
		return 0;
	n = strlen(name);
	if (n < sl)
		return 0;
	return memcmp(name + n - sl, suffix, sl) == 0;
}

/*
 * Reject paths that we know we cannot persist to as a normal
 * file: empty names, the synthetic "module@<hex>" fallback used
 * when GetFinalPathNameByHandleA fails, and NT device paths
 * starting with "\Device\".  Anything else is left to fopen()
 * to accept or reject.
 */
static int
is_unopenable_pe_path(const char *name)
{
	if (name == NULL || name[0] == 0)
		return 1;
	if (strncmp(name, "module@", 7) == 0)
		return 1;
	if (strncmp(name, "\\Device\\", 8) == 0)
		return 1;
	return 0;
}

int
zpatch_va_to_file(const struct zmap_table *maps, zaddr_t addr, size_t len,
    char *file, size_t filecap, uint64_t *offp)
{
	return zpatch_va_to_file_ex(maps, addr, len, file, filecap, offp,
	    NULL, NULL);
}

int
zpatch_va_to_file_ex(const struct zmap_table *maps, zaddr_t addr,
    size_t len, char *file, size_t filecap, uint64_t *offp,
    uint64_t *rvap, int *via_pe)
{
	const struct zmap *m;
	size_t nlen;

	if (via_pe != NULL)
		*via_pe = 0;
	if (maps == NULL || len == 0)
		return -1;
	m = zmaps_find_by_addr(maps, addr);
	if (m == NULL)
		return -1;
	/* Whole range must fit in the single mapping. */
	if (addr + (zaddr_t)len > m->end)
		return -1;
	if (m->name[0] == 0)
		return -1;
	if (is_bracketed(m->name))
		return -1;
	if (is_deleted_mapping(m->name))
		return -1;

	if (m->raw_file_offset_valid) {
		if (file != NULL && filecap > 0) {
			nlen = strlen(m->name);
			if (nlen >= filecap)
				nlen = filecap - 1;
			memcpy(file, m->name, nlen);
			file[nlen] = 0;
		}
		if (offp != NULL)
			*offp = (uint64_t)(m->offset +
			    (addr - m->start));
		return 0;
	}

	/*
	 * Synthetic image map (Windows).  Try the PE-aware path:
	 * if `m->name` is an openable PE32+ file on disk and the
	 * RVA range maps entirely to one section's raw bytes,
	 * succeed with the computed file offset.
	 */
	if (is_unopenable_pe_path(m->name))
		return -1;
	{
		uint64_t rva;
		uint64_t off = 0;

		rva = (uint64_t)(addr - m->start);
		if (zpe_file_rva_to_offset(m->name, rva, len, &off) < 0)
			return -1;
		if (file != NULL && filecap > 0) {
			nlen = strlen(m->name);
			if (nlen >= filecap)
				nlen = filecap - 1;
			memcpy(file, m->name, nlen);
			file[nlen] = 0;
		}
		if (offp != NULL)
			*offp = off;
		if (rvap != NULL)
			*rvap = rva;
		if (via_pe != NULL)
			*via_pe = 1;
		return 0;
	}
}

int
zpatch_resolve_file(struct zpatch *p, const struct zmap_table *maps)
{
	uint64_t off = 0;
	uint64_t rva = 0;
	int via_pe = 0;
	char file[ZDBG_PATCH_FILE_MAX];
	size_t n;

	if (p == NULL)
		return -1;
	p->has_file = 0;
	p->file[0] = 0;
	p->file_off = 0;
	p->has_rva = 0;
	p->rva = 0;
	if (maps == NULL)
		return -1;
	if (zpatch_va_to_file_ex(maps, p->addr, p->len, file, sizeof(file),
	    &off, &rva, &via_pe) < 0)
		return -1;
	n = strlen(file);
	if (n >= sizeof(p->file))
		n = sizeof(p->file) - 1;
	memcpy(p->file, file, n);
	p->file[n] = 0;
	p->file_off = off;
	p->has_file = 1;
	if (via_pe) {
		p->has_rva = 1;
		p->rva = rva;
	}
	return 0;
}
