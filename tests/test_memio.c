/*
 * test_memio.c - unit tests for helpers introduced for the
 * DEBUG.COM-style memory utility commands (c, m, wf, rf):
 *   - zcmd_split_quoted() (quote-aware token splitter, also
 *     used by the search command)
 *   - chunk-size math used by the patch-write chunker
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_cmd.h"
#include "zdbg_patch.h"

static int failures;

#define FAILF(...) do {                                               \
	fprintf(stderr, "FAIL %s:%d ", __FILE__, __LINE__);           \
	fprintf(stderr, __VA_ARGS__);                                 \
	fprintf(stderr, "\n");                                        \
	failures++;                                                   \
} while (0)

static void
test_qsplit_basic(void)
{
	char buf[64];
	char *argv[8];
	int argc = -1;

	if (zcmd_split_quoted("a b c", buf, sizeof(buf),
	    argv, 8, &argc) != 0)
		FAILF("split returned non-zero");
	if (argc != 3)
		FAILF("expected 3 tokens, got %d", argc);
	if (strcmp(argv[0], "a") != 0 || strcmp(argv[1], "b") != 0 ||
	    strcmp(argv[2], "c") != 0)
		FAILF("token contents wrong");
}

static void
test_qsplit_empty(void)
{
	char buf[16];
	char *argv[4];
	int argc = -1;

	if (zcmd_split_quoted("", buf, sizeof(buf), argv, 4, &argc) != 0)
		FAILF("empty split returned non-zero");
	if (argc != 0)
		FAILF("expected 0 tokens for empty input");

	if (zcmd_split_quoted("    \t  ", buf, sizeof(buf),
	    argv, 4, &argc) != 0)
		FAILF("whitespace-only split returned non-zero");
	if (argc != 0)
		FAILF("expected 0 tokens for whitespace input");
}

static void
test_qsplit_quoted_path(void)
{
	char buf[128];
	char *argv[4];
	int argc = -1;

	if (zcmd_split_quoted("wf main 20 \"C:\\\\Temp\\\\zdbg out.bin\"",
	    buf, sizeof(buf), argv, 4, &argc) != 0)
		FAILF("quoted split returned non-zero");
	if (argc != 4)
		FAILF("expected 4 tokens, got %d", argc);
	if (strcmp(argv[0], "wf") != 0)
		FAILF("argv[0] wrong");
	if (strcmp(argv[3], "C:\\\\Temp\\\\zdbg out.bin") != 0)
		FAILF("argv[3] wrong: %s", argv[3]);
}

static void
test_qsplit_overflow(void)
{
	char buf[8];
	char *argv[4];
	int argc = 0;

	/* Buffer too small: should report -1 rather than corrupt. */
	if (zcmd_split_quoted("abcdefghij", buf, sizeof(buf),
	    argv, 4, &argc) != -1)
		FAILF("expected overflow to fail");

	/* Argv too small: should report -1. */
	if (zcmd_split_quoted("a b c d e", buf, sizeof(buf),
	    argv, 4, &argc) != -1)
		FAILF("expected too-many-tokens to fail");
}

/*
 * Mirrors the chunking arithmetic used by
 * zdbg_patch_write_chunked() so the per-chunk size never exceeds
 * ZDBG_PATCH_MAX_BYTES and the chunks cover the full range
 * exactly.
 */
static void
test_chunk_split(void)
{
	size_t sizes[] = { 1, ZDBG_PATCH_MAX_BYTES,
	    ZDBG_PATCH_MAX_BYTES + 1,
	    ZDBG_PATCH_MAX_BYTES * 3,
	    ZDBG_PATCH_MAX_BYTES * 5 + 7 };
	size_t i;

	for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		size_t total = sizes[i];
		size_t off = 0;
		size_t expected_chunks =
		    (total + ZDBG_PATCH_MAX_BYTES - 1) /
		    ZDBG_PATCH_MAX_BYTES;
		size_t got = 0;

		while (off < total) {
			size_t chunk = total - off;
			if (chunk > ZDBG_PATCH_MAX_BYTES)
				chunk = ZDBG_PATCH_MAX_BYTES;
			if (chunk == 0 || chunk > ZDBG_PATCH_MAX_BYTES)
				FAILF("bad chunk size for total=%zu", total);
			off += chunk;
			got++;
		}
		if (off != total)
			FAILF("chunks didn't sum to total %zu", total);
		if (got != expected_chunks)
			FAILF("expected %zu chunks, got %zu",
			    expected_chunks, got);
	}
}

int
main(void)
{
	test_qsplit_basic();
	test_qsplit_empty();
	test_qsplit_quoted_path();
	test_qsplit_overflow();
	test_chunk_split();

	if (failures != 0) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_memio ok\n");
	return 0;
}
