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

#endif /* ZDBG_MEM_H */
