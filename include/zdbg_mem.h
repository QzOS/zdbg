/*
 * zdbg_mem.h - small memory utility helpers.
 */

#ifndef ZDBG_MEM_H
#define ZDBG_MEM_H

#include "zdbg.h"

void zmem_hexdump(zaddr_t addr, const void *buf, size_t len);
int  zmem_parse_bytes(const char *s, uint8_t *buf, size_t buflen, size_t *lenp);
void zmem_fill_pattern(uint8_t *dst, size_t len, const uint8_t *pat,
    size_t patlen);

/* --- search helpers ------------------------------------------- */

#define ZDBG_SEARCH_MAX_PATTERN   256
#define ZDBG_SEARCH_DEFAULT_LIMIT 64
#define ZDBG_SEARCH_CHUNK         65536

/*
 * Match callback for buffer search.  `addr` is the absolute
 * address of the match (base + offset within buf).  Return 0 to
 * continue, 1 to stop (e.g. result-limit reached), negative for
 * error.
 */
typedef int (*zmem_match_cb)(zaddr_t addr, void *arg);

/*
 * Search the buffer [buf, buf+len) for occurrences of the byte
 * pattern [pat, pat+patlen).  For every match the callback is
 * invoked with the absolute address `base + offset`.  Overlapping
 * matches are reported (e.g. pattern "ABA" in "ABABA" matches at
 * offsets 0 and 2).  Returns 0 on completion, 1 if the callback
 * stopped the scan, -1 on bad arguments (NULL/zero-length).
 */
int zmem_search_buffer(zaddr_t base, const uint8_t *buf, size_t len,
    const uint8_t *pat, size_t patlen, zmem_match_cb cb, void *arg);

/*
 * Pattern builders.  Each writes the encoded pattern bytes into
 * buf (capacity cap) and stores the produced length in *lenp.
 * Return 0 on success, -1 if the result would exceed `cap` or
 * the input is invalid.  None of these append an implicit NUL
 * terminator to the produced pattern.
 *
 * zmem_make_ascii_pattern() supports a small escape set:
 *   \n \r \t \\ \" \xNN
 * Other backslash sequences are rejected.
 */
int zmem_make_ascii_pattern(const char *s, uint8_t *buf, size_t cap,
    size_t *lenp);
int zmem_make_utf16le_pattern(const char *s, uint8_t *buf, size_t cap,
    size_t *lenp);
int zmem_make_u32_pattern(uint32_t v, uint8_t *buf, size_t cap,
    size_t *lenp);
int zmem_make_u64_pattern(uint64_t v, uint8_t *buf, size_t cap,
    size_t *lenp);

#endif /* ZDBG_MEM_H */
