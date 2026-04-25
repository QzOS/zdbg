/*
 * zdbg_stdio.h - target stdio redirection configuration.
 *
 * Configuration applied to launched targets only.  Attach is
 * unaffected.  Capture mode is file-backed (no pipes, no
 * background reader threads, no PTY/ConPTY), so output buffered
 * by the target may not appear in the file until the target
 * flushes or exits.
 */

#ifndef ZDBG_STDIO_H
#define ZDBG_STDIO_H

#include <stddef.h>

#define ZDBG_STDIO_PATH_MAX 512

enum zstdio_mode {
	ZSTDIO_INHERIT = 0,
	ZSTDIO_NULL,
	ZSTDIO_FILE,
	ZSTDIO_CAPTURE,
	ZSTDIO_STDOUT		/* stderr only: redirect stderr to stdout */
};

struct zstdio_slot {
	enum zstdio_mode mode;
	char path[ZDBG_STDIO_PATH_MAX];
};

struct zstdio_config {
	struct zstdio_slot in;
	struct zstdio_slot out;
	struct zstdio_slot err;
};

/* Initialize all three slots to inherit. */
void zstdio_config_init(struct zstdio_config *c);

/* Restore all three slots to inherit (alias of init). */
void zstdio_config_reset(struct zstdio_config *c);

/* Set a slot to inherit/null, copy a path (FILE), or set CAPTURE. */
int  zstdio_set_inherit(struct zstdio_slot *s);
int  zstdio_set_null(struct zstdio_slot *s);
int  zstdio_set_file(struct zstdio_slot *s, const char *path);
int  zstdio_set_capture(struct zstdio_slot *s, const char *which);
int  zstdio_set_stdout(struct zstdio_slot *s); /* stderr -> stdout */

/* Platform-specific null device path: "/dev/null" or "NUL". */
const char *zstdio_null_path(void);

/*
 * Build a unique capture file path in the system temp directory.
 *   which: "stdout" or "stderr".
 * Writes a NUL-terminated string into out (capacity outlen).
 * Returns 0 on success, -1 on failure.
 */
int zstdio_make_capture_path(const char *which, char *out, size_t outlen);

/* Render a slot to a human-readable description (no trailing NL). */
void zstdio_describe(const struct zstdio_slot *s, char *out, size_t outlen);

/*
 * Return the configured output path for the slot, or NULL when
 * the slot has no path (inherit/null/stdout-link).  For FILE and
 * CAPTURE this returns slot->path.
 */
const char *zstdio_slot_path(const struct zstdio_slot *s);

#endif /* ZDBG_STDIO_H */
