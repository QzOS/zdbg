/*
 * zdbg_machine.h - executable machine detection.
 *
 * Reads the minimal headers of an ELF or PE executable on disk
 * and reports the corresponding zdbg architecture identifier.
 * Used by the launch path so that the debugger does not silently
 * try to debug a file whose machine type the active backend does
 * not support.
 *
 * Detection is intentionally tiny:
 *   - ELF64 little-endian only (ELFCLASS64 / ELFDATA2LSB)
 *   - PE32+ (IMAGE_NT_OPTIONAL_HDR64_MAGIC)
 *
 * 32-bit ELF/PE and other unusual files return -1 with a clear
 * error string written into the caller-provided buffer.
 */

#ifndef ZDBG_MACHINE_H
#define ZDBG_MACHINE_H

#include <stddef.h>

#include "zdbg_arch.h"

/*
 * Inspect the file at `path` and write the detected zdbg
 * architecture to *archp on success.
 *
 * Return codes:
 *   0  detected successfully (*archp valid)
 *  -1  could not detect: file open failure, short read, or the
 *      file is not an ELF/PE executable.  Callers may choose to
 *      fall through and let the OS backend produce its own error.
 *  -2  detected but unsupported: ELF32, PE32, big-endian ELF,
 *      unknown machine, etc.  Callers should refuse to launch.
 *
 * When `err` is non-NULL and `errcap` > 0 a short, NUL-terminated
 * description of the failure is written into `err` (and on
 * success it is left as the empty string).
 */
int zmachine_detect_file(const char *path, enum zarch *archp,
    char *err, size_t errcap);

#endif /* ZDBG_MACHINE_H */
