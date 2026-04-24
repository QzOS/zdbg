/*
 * zdbg_pe.h - minimal PE file helper used by the patch journal
 * to translate a PE32+ RVA range into a raw on-disk file offset.
 *
 * This is *not* a PE editor.  It only validates that a contiguous
 * RVA range is fully backed by raw bytes inside one PE section
 * and computes the matching file offset.  No section growth, no
 * relocation editing, no checksum repair, no Authenticode work.
 *
 * The helper is implemented in portable C99 against the on-disk
 * PE layout (no <windows.h>) so it can be unit-tested on any
 * host, and so its safety rules do not depend on the loader.
 */

#ifndef ZDBG_PE_H
#define ZDBG_PE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Translate [rva, rva + len) of the PE32+ file at `path` to a
 * raw file offset.  On success, *offp receives the offset and 0
 * is returned.  On any failure (bad headers, not PE32+, range
 * spans/leaves a section, range falls in BSS/uninitialized tail
 * bytes, len == 0, integer overflow, file too short, unopenable)
 * the function returns -1 and *offp is left unchanged.
 *
 * Safety rule for each section:
 *
 *   raw-backed range = [VirtualAddress, VirtualAddress + SizeOfRawData)
 *
 * The whole [rva, rva+len) range must lie inside one section's
 * raw-backed range *and* PointerToRawData + (rva - VirtualAddress)
 * + len must fit in the file size.
 */
int zpe_file_rva_to_offset(const char *path, uint64_t rva, size_t len,
    uint64_t *offp);

#endif /* ZDBG_PE_H */
