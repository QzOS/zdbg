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
