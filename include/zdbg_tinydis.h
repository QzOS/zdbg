/*
 * zdbg_tinydis.h - tiny disassembler.
 *
 * Recognises the same subset that ztinyasm encodes.  Unknown
 * bytes are emitted as "db 0xNN" which is intentionally
 * DEBUG.COM-like.
 */

#ifndef ZDBG_TINYDIS_H
#define ZDBG_TINYDIS_H

#include "zdbg.h"

struct ztinydis {
	zaddr_t addr;
	uint8_t bytes[16];
	size_t len;
	char text[64];
};

int  ztinydis_one(zaddr_t addr, const uint8_t *buf, size_t buflen,
    struct ztinydis *out);
void ztinydis_print(const struct ztinydis *d);

#endif /* ZDBG_TINYDIS_H */
