/*
 * test_search.c - unit tests for buffer search and pattern
 * builders introduced for the region-aware `s` command.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_mem.h"

static int failures;

#define FAILF(...) do {                                               \
	fprintf(stderr, "FAIL %s:%d ", __FILE__, __LINE__);           \
	fprintf(stderr, __VA_ARGS__);                                 \
	fprintf(stderr, "\n");                                        \
	failures++;                                                   \
} while (0)

struct collect_ctx {
	zaddr_t addrs[16];
	int n;
	int stop_at;
};

static int
collect_cb(zaddr_t addr, void *arg)
{
	struct collect_ctx *c = (struct collect_ctx *)arg;

	if (c->n < (int)(sizeof(c->addrs) / sizeof(c->addrs[0])))
		c->addrs[c->n++] = addr;
	if (c->stop_at > 0 && c->n >= c->stop_at)
		return 1;
	return 0;
}

static void
test_search_single(void)
{
	const uint8_t haystack[] = { 0x90, 0x90, 0x48, 0x89, 0xe5, 0xc3 };
	const uint8_t pat[] = { 0x48, 0x89, 0xe5 };
	struct collect_ctx c = { { 0 }, 0, 0 };

	if (zmem_search_buffer(0x1000, haystack, sizeof(haystack),
	    pat, sizeof(pat), collect_cb, &c) != 0)
		FAILF("search returned non-zero");
	if (c.n != 1 || c.addrs[0] != 0x1002)
		FAILF("expected single match at 0x1002, got n=%d", c.n);
}

static void
test_search_multi(void)
{
	const uint8_t haystack[] = { 0xab, 0xab, 0xab, 0xab };
	const uint8_t pat[] = { 0xab, 0xab };
	struct collect_ctx c = { { 0 }, 0, 0 };

	if (zmem_search_buffer(0, haystack, sizeof(haystack),
	    pat, sizeof(pat), collect_cb, &c) != 0)
		FAILF("search non-zero");
	/* Overlapping matches at offsets 0,1,2 */
	if (c.n != 3)
		FAILF("expected 3 overlapping matches, got %d", c.n);
}

static void
test_search_overlap_aba(void)
{
	const uint8_t haystack[] = { 'A', 'B', 'A', 'B', 'A' };
	const uint8_t pat[] = { 'A', 'B', 'A' };
	struct collect_ctx c = { { 0 }, 0, 0 };

	if (zmem_search_buffer(0, haystack, sizeof(haystack),
	    pat, sizeof(pat), collect_cb, &c) != 0)
		FAILF("search non-zero");
	if (c.n != 2 || c.addrs[0] != 0 || c.addrs[1] != 2)
		FAILF("expected ABA matches at 0 and 2, got n=%d", c.n);
}

static void
test_search_no_match(void)
{
	const uint8_t haystack[] = { 0x00, 0x00, 0x00 };
	const uint8_t pat[] = { 0xff };
	struct collect_ctx c = { { 0 }, 0, 0 };

	if (zmem_search_buffer(0, haystack, sizeof(haystack),
	    pat, sizeof(pat), collect_cb, &c) != 0)
		FAILF("search non-zero on no match");
	if (c.n != 0)
		FAILF("expected no matches, got %d", c.n);
}

static void
test_search_zero_pat(void)
{
	const uint8_t haystack[] = { 0 };
	const uint8_t pat[] = { 0 };
	struct collect_ctx c = { { 0 }, 0, 0 };

	if (zmem_search_buffer(0, haystack, 1, pat, 0, collect_cb, &c) != -1)
		FAILF("expected -1 for zero-length pattern");
}

static void
test_search_callback_stop(void)
{
	const uint8_t haystack[8] = { 1, 1, 1, 1, 1, 1, 1, 1 };
	const uint8_t pat[1] = { 1 };
	struct collect_ctx c = { { 0 }, 0, 2 };
	int r;

	r = zmem_search_buffer(0, haystack, sizeof(haystack),
	    pat, sizeof(pat), collect_cb, &c);
	if (r != 1)
		FAILF("expected 1 (stopped) from callback, got %d", r);
	if (c.n != 2)
		FAILF("expected exactly 2 collected, got %d", c.n);
}

static void
test_ascii_pattern(void)
{
	uint8_t buf[32];
	size_t len = 0;

	if (zmem_make_ascii_pattern("hi", buf, sizeof(buf), &len) != 0)
		FAILF("ascii build failed");
	if (len != 2 || buf[0] != 'h' || buf[1] != 'i')
		FAILF("ascii bytes wrong");
}

static void
test_ascii_pattern_escape(void)
{
	uint8_t buf[32];
	size_t len = 0;

	if (zmem_make_ascii_pattern("a\\n\\x41\\\\\\\"", buf, sizeof(buf),
	    &len) != 0)
		FAILF("ascii escape build failed");
	if (len != 5 || buf[0] != 'a' || buf[1] != '\n' || buf[2] != 'A' ||
	    buf[3] != '\\' || buf[4] != '"')
		FAILF("ascii escape bytes wrong (len=%zu)", len);

	/* Bad escape rejected */
	if (zmem_make_ascii_pattern("\\q", buf, sizeof(buf), &len) != -1)
		FAILF("expected reject of \\q");

	/* Bad hex escape rejected */
	if (zmem_make_ascii_pattern("\\xZZ", buf, sizeof(buf), &len) != -1)
		FAILF("expected reject of \\xZZ");
}

static void
test_utf16le_pattern(void)
{
	uint8_t buf[32];
	size_t len = 0;
	const uint8_t expect[] = {
	    'h', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0
	};

	if (zmem_make_utf16le_pattern("hello", buf, sizeof(buf), &len) != 0)
		FAILF("wstr build failed");
	if (len != sizeof(expect) || memcmp(buf, expect, sizeof(expect)) != 0)
		FAILF("wstr encoding wrong");
}

static void
test_u32_pattern(void)
{
	uint8_t buf[8];
	size_t len = 0;

	if (zmem_make_u32_pattern(0x12345678u, buf, sizeof(buf), &len) != 0)
		FAILF("u32 build failed");
	if (len != 4 || buf[0] != 0x78 || buf[1] != 0x56 ||
	    buf[2] != 0x34 || buf[3] != 0x12)
		FAILF("u32 LE encoding wrong");
}

static void
test_u64_pattern(void)
{
	uint8_t buf[8];
	size_t len = 0;
	int i;
	uint8_t expect[8] = {
	    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
	};

	if (zmem_make_u64_pattern(0x1122334455667788ull, buf, sizeof(buf),
	    &len) != 0)
		FAILF("u64 build failed");
	if (len != 8)
		FAILF("u64 length wrong");
	for (i = 0; i < 8; i++) {
		if (buf[i] != expect[i])
			FAILF("u64 byte %d wrong", i);
	}
}

static void
test_u32_too_small(void)
{
	uint8_t buf[2];
	size_t len = 0;

	if (zmem_make_u32_pattern(0, buf, sizeof(buf), &len) != -1)
		FAILF("expected -1 when buffer too small");
}

int
main(void)
{
	test_search_single();
	test_search_multi();
	test_search_overlap_aba();
	test_search_no_match();
	test_search_zero_pat();
	test_search_callback_stop();
	test_ascii_pattern();
	test_ascii_pattern_escape();
	test_utf16le_pattern();
	test_u32_pattern();
	test_u64_pattern();
	test_u32_too_small();

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_search ok\n");
	return 0;
}
