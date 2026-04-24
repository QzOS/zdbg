/*
 * tinydis.c - tiny disassembler, matches the ztinyasm subset.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_tinydis.h"

static void
copy_bytes(struct ztinydis *out, const uint8_t *buf, size_t n)
{
	size_t i;
	if (n > sizeof(out->bytes))
		n = sizeof(out->bytes);
	for (i = 0; i < n; i++)
		out->bytes[i] = buf[i];
	out->len = n;
}

static int32_t
read_rel32(const uint8_t *p)
{
	uint32_t v;
	v  = (uint32_t)p[0];
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;
	return (int32_t)v;
}

int
ztinydis_one(zaddr_t addr, const uint8_t *buf, size_t buflen,
    struct ztinydis *out)
{
	if (buf == NULL || buflen == 0 || out == NULL)
		return -1;

	memset(out, 0, sizeof(*out));
	out->addr = addr;

	switch (buf[0]) {
	case 0x90:
		copy_bytes(out, buf, 1);
		snprintf(out->text, sizeof(out->text), "nop");
		return 0;
	case 0xcc:
		copy_bytes(out, buf, 1);
		snprintf(out->text, sizeof(out->text), "int3");
		return 0;
	case 0xc3:
		copy_bytes(out, buf, 1);
		snprintf(out->text, sizeof(out->text), "ret");
		return 0;
	case 0xeb:
		if (buflen < 2)
			break;
		copy_bytes(out, buf, 2);
		snprintf(out->text, sizeof(out->text), "jmp8 0x%llx",
		    (unsigned long long)(addr + 2 + (int8_t)buf[1]));
		return 0;
	case 0x74:
		if (buflen < 2)
			break;
		copy_bytes(out, buf, 2);
		snprintf(out->text, sizeof(out->text), "jz8 0x%llx",
		    (unsigned long long)(addr + 2 + (int8_t)buf[1]));
		return 0;
	case 0x75:
		if (buflen < 2)
			break;
		copy_bytes(out, buf, 2);
		snprintf(out->text, sizeof(out->text), "jnz8 0x%llx",
		    (unsigned long long)(addr + 2 + (int8_t)buf[1]));
		return 0;
	case 0xe9:
		if (buflen < 5)
			break;
		copy_bytes(out, buf, 5);
		snprintf(out->text, sizeof(out->text), "jmp 0x%llx",
		    (unsigned long long)(addr + 5 + read_rel32(buf + 1)));
		return 0;
	case 0x0f:
		if (buflen >= 6 && buf[1] == 0x84) {
			copy_bytes(out, buf, 6);
			snprintf(out->text, sizeof(out->text), "jz 0x%llx",
			    (unsigned long long)(addr + 6 +
			    read_rel32(buf + 2)));
			return 0;
		}
		if (buflen >= 6 && buf[1] == 0x85) {
			copy_bytes(out, buf, 6);
			snprintf(out->text, sizeof(out->text), "jnz 0x%llx",
			    (unsigned long long)(addr + 6 +
			    read_rel32(buf + 2)));
			return 0;
		}
		break;
	default:
		break;
	}

	/* unknown byte: db 0xNN */
	copy_bytes(out, buf, 1);
	snprintf(out->text, sizeof(out->text), "db 0x%02x", buf[0]);
	return 0;
}

void
ztinydis_print(const struct ztinydis *d)
{
	size_t i;
	char hex[64];
	size_t pos = 0;

	if (d == NULL)
		return;
	hex[0] = 0;
	for (i = 0; i < d->len && pos + 3 < sizeof(hex); i++) {
		pos += (size_t)snprintf(hex + pos, sizeof(hex) - pos, "%02x ",
		    d->bytes[i]);
	}
	printf("%016llx  %-20s  %s\n",
	    (unsigned long long)d->addr, hex, d->text);
}
