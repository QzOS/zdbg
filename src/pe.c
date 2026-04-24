/*
 * pe.c - portable PE32+ file parser used by the patch journal.
 *
 * This is intentionally narrow: it exists only to translate a
 * single contiguous RVA range to a raw on-disk file offset, so
 * `pw` can write recorded byte patches back to a Windows PE
 * image when the bytes provably exist on disk.
 *
 * Constraints:
 *   - PE32+ only (IMAGE_NT_OPTIONAL_HDR64_MAGIC, 0x20b).
 *   - The whole [rva, rva+len) must sit inside one section's
 *     raw-backed range [VirtualAddress, VirtualAddress +
 *     SizeOfRawData).  Tail bytes that exist only virtually
 *     (BSS / SizeOfRawData < VirtualSize) are *not* file-backed
 *     and are refused.
 *   - The resulting [file_off, file_off+len) must fit in the
 *     file size on disk.
 *   - All header fields are read with little-endian helpers
 *     and bounds-checked against the actual file size.  No
 *     <windows.h>; no struct overlay; no alignment assumptions.
 */

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>

#include "zdbg_pe.h"

/* PE constants we care about. */
#define ZPE_DOS_SIGNATURE      0x5a4dU         /* "MZ" */
#define ZPE_NT_SIGNATURE       0x00004550U     /* "PE\0\0" */
#define ZPE_OPT_HDR64_MAGIC    0x020bU
#define ZPE_OPT_HDR32_MAGIC    0x010bU

#define ZPE_DOS_HDR_SIZE       64
#define ZPE_E_LFANEW_OFF       0x3c
#define ZPE_FILE_HDR_SIZE      20
#define ZPE_SECTION_HDR_SIZE   40
#define ZPE_MAX_E_LFANEW       0x100000
#define ZPE_MAX_SECTIONS       96

/* Offsets inside an IMAGE_FILE_HEADER. */
#define ZPE_FH_NUM_SECTIONS    2
#define ZPE_FH_SIZE_OPT_HDR    16

/* Offsets inside an IMAGE_SECTION_HEADER. */
#define ZPE_SH_VIRTUAL_SIZE    8
#define ZPE_SH_VIRTUAL_ADDR    12
#define ZPE_SH_RAW_SIZE        16
#define ZPE_SH_RAW_PTR         20

static uint16_t
zpe_rd16(const uint8_t *p)
{
	return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t
zpe_rd32(const uint8_t *p)
{
	return (uint32_t)p[0] |
	    ((uint32_t)p[1] << 8) |
	    ((uint32_t)p[2] << 16) |
	    ((uint32_t)p[3] << 24);
}

/*
 * Read exactly `n` bytes at file offset `off` into `buf`.
 * Returns 0 on success, -1 on any short read or seek failure.
 */
static int
zpe_read_at(FILE *f, uint64_t off, void *buf, size_t n)
{
	if (f == NULL || buf == NULL || n == 0)
		return -1;
	/*
	 * fseek's offset argument is `long`, which may be 32-bit
	 * on some hosts (notably 32-bit Windows).  Refuse offsets
	 * that would not fit cleanly rather than silently
	 * truncating.
	 */
	if (off > (uint64_t)LONG_MAX)
		return -1;
	if (fseek(f, (long)off, SEEK_SET) != 0)
		return -1;
	if (fread(buf, 1, n, f) != n)
		return -1;
	return 0;
}

static int
zpe_file_size(FILE *f, uint64_t *outp)
{
	long pos;
	if (fseek(f, 0, SEEK_END) != 0)
		return -1;
	pos = ftell(f);
	if (pos < 0)
		return -1;
	*outp = (uint64_t)pos;
	return 0;
}

/* Add with overflow check; returns 0 on overflow. */
static int
zpe_add_u64(uint64_t a, uint64_t b, uint64_t *outp)
{
	if (a > UINT64_MAX - b)
		return 0;
	*outp = a + b;
	return 1;
}

int
zpe_file_rva_to_offset(const char *path, uint64_t rva, size_t len,
    uint64_t *offp)
{
	FILE *f;
	uint8_t dos[ZPE_DOS_HDR_SIZE];
	uint8_t pe_sig[4];
	uint8_t fh[ZPE_FILE_HDR_SIZE];
	uint8_t opt_magic[2];
	uint64_t fsize = 0;
	uint64_t e_lfanew;
	uint64_t fh_off;
	uint64_t opt_off;
	uint64_t sec_off;
	uint64_t sec_end;
	uint64_t rva_end;
	uint16_t nsec;
	uint16_t opt_size;
	uint16_t magic;
	int i;
	int rc = -1;

	if (path == NULL || path[0] == 0 || offp == NULL)
		return -1;
	if (len == 0)
		return -1;
	/* rva + len must not wrap. */
	if (!zpe_add_u64(rva, (uint64_t)len, &rva_end))
		return -1;

	f = fopen(path, "rb");
	if (f == NULL)
		return -1;

	if (zpe_file_size(f, &fsize) < 0)
		goto out;
	if (fsize < ZPE_DOS_HDR_SIZE)
		goto out;

	if (zpe_read_at(f, 0, dos, sizeof(dos)) < 0)
		goto out;
	if (zpe_rd16(dos) != ZPE_DOS_SIGNATURE)
		goto out;

	e_lfanew = (uint64_t)zpe_rd32(dos + ZPE_E_LFANEW_OFF);
	if (e_lfanew == 0 || e_lfanew > ZPE_MAX_E_LFANEW)
		goto out;
	/* Need PE signature + file header at e_lfanew. */
	if (e_lfanew + 4 + ZPE_FILE_HDR_SIZE > fsize)
		goto out;

	if (zpe_read_at(f, e_lfanew, pe_sig, sizeof(pe_sig)) < 0)
		goto out;
	if (zpe_rd32(pe_sig) != ZPE_NT_SIGNATURE)
		goto out;

	fh_off = e_lfanew + 4;
	if (zpe_read_at(f, fh_off, fh, sizeof(fh)) < 0)
		goto out;

	nsec = zpe_rd16(fh + ZPE_FH_NUM_SECTIONS);
	opt_size = zpe_rd16(fh + ZPE_FH_SIZE_OPT_HDR);
	if (nsec == 0 || nsec > ZPE_MAX_SECTIONS)
		goto out;
	if (opt_size < 2)
		goto out;

	opt_off = fh_off + ZPE_FILE_HDR_SIZE;
	if (opt_off + opt_size > fsize)
		goto out;
	/* PE32+ optional-header magic. */
	if (zpe_read_at(f, opt_off, opt_magic, sizeof(opt_magic)) < 0)
		goto out;
	magic = zpe_rd16(opt_magic);
	if (magic != ZPE_OPT_HDR64_MAGIC)
		goto out;	/* PE32 / WOW64 / ROM not supported */

	sec_off = opt_off + opt_size;
	sec_end = sec_off +
	    (uint64_t)nsec * (uint64_t)ZPE_SECTION_HDR_SIZE;
	if (sec_end > fsize)
		goto out;

	for (i = 0; i < (int)nsec; i++) {
		uint8_t sh[ZPE_SECTION_HDR_SIZE];
		uint64_t va;
		uint64_t raw_size;
		uint64_t raw_ptr;
		uint64_t cur_off;
		uint64_t end_off;
		uint64_t va_end;

		if (zpe_read_at(f,
		    sec_off + (uint64_t)i * ZPE_SECTION_HDR_SIZE,
		    sh, sizeof(sh)) < 0)
			goto out;

		va = (uint64_t)zpe_rd32(sh + ZPE_SH_VIRTUAL_ADDR);
		raw_size = (uint64_t)zpe_rd32(sh + ZPE_SH_RAW_SIZE);
		raw_ptr = (uint64_t)zpe_rd32(sh + ZPE_SH_RAW_PTR);

		if (raw_size == 0)
			continue;	/* nothing on disk for this section */
		if (!zpe_add_u64(va, raw_size, &va_end))
			continue;

		/* Whole [rva, rva+len) must lie inside [va, va+raw_size). */
		if (rva < va)
			continue;
		if (rva_end > va_end)
			continue;

		/*
		 * Compute file offset and validate it fits in file.
		 * raw_ptr + (rva - va) + len <= fsize.
		 */
		if (!zpe_add_u64(raw_ptr, rva - va, &cur_off))
			goto out;
		if (!zpe_add_u64(cur_off, (uint64_t)len, &end_off))
			goto out;
		if (end_off > fsize)
			goto out;
		*offp = cur_off;
		rc = 0;
		goto out;
	}
	/* No section claimed the whole range. */
	rc = -1;

out:
	fclose(f);
	return rc;
}
