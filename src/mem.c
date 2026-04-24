/*
 * mem.c - memory utility helpers.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "zdbg_mem.h"

void
zmem_hexdump(zaddr_t addr, const void *buf, size_t len)
{
	const uint8_t *p = (const uint8_t *)buf;
	size_t off;

	if (buf == NULL)
		return;

	for (off = 0; off < len; off += 16) {
		size_t i;
		size_t row = len - off;
		if (row > 16)
			row = 16;

		printf("%016llx ", (unsigned long long)(addr + off));
		for (i = 0; i < 16; i++) {
			if (i == 8)
				printf(" ");
			if (i < row)
				printf(" %02x", p[off + i]);
			else
				printf("   ");
		}
		printf("  ");
		for (i = 0; i < row; i++) {
			unsigned char c = p[off + i];
			if (c >= 0x20 && c < 0x7f)
				putchar((int)c);
			else
				putchar('.');
		}
		putchar('\n');
	}
}

static int
hexval(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return 10 + (c - 'a');
	if (c >= 'A' && c <= 'F')
		return 10 + (c - 'A');
	return -1;
}

int
zmem_parse_bytes(const char *s, uint8_t *buf, size_t buflen, size_t *lenp)
{
	size_t n = 0;

	if (s == NULL || buf == NULL)
		return -1;

	while (*s) {
		unsigned int v;
		int d1, d2;

		/* skip separators */
		while (*s == ' ' || *s == '\t' || *s == ',')
			s++;
		if (*s == 0)
			break;

		/* optional 0x / 0X */
		if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
			s += 2;

		d1 = hexval((unsigned char)s[0]);
		if (d1 < 0)
			return -1;
		s++;

		d2 = hexval((unsigned char)s[0]);
		if (d2 >= 0) {
			v = (unsigned int)((d1 << 4) | d2);
			s++;
		} else {
			v = (unsigned int)d1;
		}

		if (v > 0xff)
			return -1;

		if (n >= buflen)
			return -1;
		buf[n++] = (uint8_t)v;

		/* must be end-of-string or separator */
		if (*s != 0 && *s != ' ' && *s != '\t' && *s != ',')
			return -1;
	}

	if (lenp != NULL)
		*lenp = n;
	return 0;
}

void
zmem_fill_pattern(uint8_t *dst, size_t len, const uint8_t *pat, size_t patlen)
{
	size_t i;

	if (dst == NULL || pat == NULL || patlen == 0)
		return;
	for (i = 0; i < len; i++)
		dst[i] = pat[i % patlen];
}

/* --- search helpers ------------------------------------------- */

int
zmem_search_buffer(zaddr_t base, const uint8_t *buf, size_t len,
    const uint8_t *pat, size_t patlen, zmem_match_cb cb, void *arg)
{
	size_t i;
	uint8_t first;
	int r;

	if (buf == NULL || pat == NULL || patlen == 0 || cb == NULL)
		return -1;
	if (len < patlen)
		return 0;

	first = pat[0];
	for (i = 0; i + patlen <= len; i++) {
		if (buf[i] != first)
			continue;
		if (patlen > 1 && memcmp(buf + i + 1, pat + 1, patlen - 1) != 0)
			continue;
		r = cb(base + (zaddr_t)i, arg);
		if (r < 0)
			return -1;
		if (r > 0)
			return 1;
	}
	return 0;
}

/*
 * Decode a single hex digit; -1 on non-hex.  Local helper kept
 * separate from the parse_bytes hexval() above to keep this
 * section self-contained.
 */
static int
ascii_hex(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return 10 + (c - 'a');
	if (c >= 'A' && c <= 'F')
		return 10 + (c - 'A');
	return -1;
}

int
zmem_make_ascii_pattern(const char *s, uint8_t *buf, size_t cap, size_t *lenp)
{
	size_t n = 0;

	if (s == NULL || buf == NULL)
		return -1;
	while (*s) {
		uint8_t b;

		if (*s != '\\') {
			b = (uint8_t)*s++;
		} else {
			s++;
			switch (*s) {
			case 'n': b = '\n'; s++; break;
			case 'r': b = '\r'; s++; break;
			case 't': b = '\t'; s++; break;
			case '\\': b = '\\'; s++; break;
			case '"': b = '"'; s++; break;
			case 'x': {
				int d1, d2;
				s++;
				d1 = ascii_hex((unsigned char)s[0]);
				if (d1 < 0)
					return -1;
				d2 = ascii_hex((unsigned char)s[1]);
				if (d2 < 0)
					return -1;
				b = (uint8_t)((d1 << 4) | d2);
				s += 2;
				break;
			}
			default:
				return -1;
			}
		}
		if (n >= cap)
			return -1;
		buf[n++] = b;
	}
	if (lenp != NULL)
		*lenp = n;
	return 0;
}

int
zmem_make_utf16le_pattern(const char *s, uint8_t *buf, size_t cap,
    size_t *lenp)
{
	uint8_t tmp[ZDBG_SEARCH_MAX_PATTERN];
	size_t n = 0;
	size_t i;

	if (s == NULL || buf == NULL)
		return -1;
	if (zmem_make_ascii_pattern(s, tmp, sizeof(tmp), &n) < 0)
		return -1;
	if (n * 2 > cap)
		return -1;
	for (i = 0; i < n; i++) {
		buf[i * 2] = tmp[i];
		buf[i * 2 + 1] = 0;
	}
	if (lenp != NULL)
		*lenp = n * 2;
	return 0;
}

int
zmem_make_u32_pattern(uint32_t v, uint8_t *buf, size_t cap, size_t *lenp)
{
	if (buf == NULL || cap < 4)
		return -1;
	buf[0] = (uint8_t)(v & 0xff);
	buf[1] = (uint8_t)((v >> 8) & 0xff);
	buf[2] = (uint8_t)((v >> 16) & 0xff);
	buf[3] = (uint8_t)((v >> 24) & 0xff);
	if (lenp != NULL)
		*lenp = 4;
	return 0;
}

int
zmem_make_u64_pattern(uint64_t v, uint8_t *buf, size_t cap, size_t *lenp)
{
	int i;

	if (buf == NULL || cap < 8)
		return -1;
	for (i = 0; i < 8; i++)
		buf[i] = (uint8_t)((v >> (i * 8)) & 0xff);
	if (lenp != NULL)
		*lenp = 8;
	return 0;
}
