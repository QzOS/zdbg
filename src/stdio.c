/*
 * stdio.c - target stdio configuration helpers.
 *
 * Pure data manipulation only.  Backend-specific application of
 * the configuration (open/dup2 on Linux, STARTUPINFOA on Windows)
 * lives in the target backends.
 */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#  define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  include <windows.h>
#  include <process.h>
#  define ZDBG_GETPID() ((unsigned)_getpid())
#else
#  include <unistd.h>
#  define ZDBG_GETPID() ((unsigned)getpid())
#endif

#include "zdbg_stdio.h"

void
zstdio_config_init(struct zstdio_config *c)
{
	if (c == NULL)
		return;
	memset(c, 0, sizeof(*c));
	c->in.mode = ZSTDIO_INHERIT;
	c->out.mode = ZSTDIO_INHERIT;
	c->err.mode = ZSTDIO_INHERIT;
}

void
zstdio_config_reset(struct zstdio_config *c)
{
	zstdio_config_init(c);
}

int
zstdio_set_inherit(struct zstdio_slot *s)
{
	if (s == NULL)
		return -1;
	s->mode = ZSTDIO_INHERIT;
	s->path[0] = 0;
	return 0;
}

int
zstdio_set_null(struct zstdio_slot *s)
{
	if (s == NULL)
		return -1;
	s->mode = ZSTDIO_NULL;
	s->path[0] = 0;
	return 0;
}

int
zstdio_set_file(struct zstdio_slot *s, const char *path)
{
	size_t n;

	if (s == NULL || path == NULL || path[0] == 0)
		return -1;
	n = strlen(path);
	if (n >= sizeof(s->path))
		return -1;
	s->mode = ZSTDIO_FILE;
	memcpy(s->path, path, n);
	s->path[n] = 0;
	return 0;
}

int
zstdio_set_capture(struct zstdio_slot *s, const char *which)
{
	char path[ZDBG_STDIO_PATH_MAX];

	if (s == NULL || which == NULL)
		return -1;
	if (zstdio_make_capture_path(which, path, sizeof(path)) < 0)
		return -1;
	s->mode = ZSTDIO_CAPTURE;
	memcpy(s->path, path, strlen(path) + 1);
	return 0;
}

int
zstdio_set_stdout(struct zstdio_slot *s)
{
	if (s == NULL)
		return -1;
	s->mode = ZSTDIO_STDOUT;
	s->path[0] = 0;
	return 0;
}

const char *
zstdio_null_path(void)
{
#if defined(_WIN32)
	return "NUL";
#else
	return "/dev/null";
#endif
}

static unsigned long zstdio_capture_counter;

static void
zstdio_temp_dir(char *out, size_t outlen)
{
#if defined(_WIN32)
	DWORD n;

	n = GetTempPathA((DWORD)outlen, out);
	if (n == 0 || n >= outlen) {
		if (outlen >= 3) {
			out[0] = 'C'; out[1] = ':';
			out[2] = '\\'; out[3] = 0;
		} else if (outlen > 0) {
			out[0] = 0;
		}
		return;
	}
	/* GetTempPathA includes trailing backslash. */
#else
	const char *t = getenv("TMPDIR");

	if (t == NULL || t[0] == 0)
		t = "/tmp";
	if (outlen == 0)
		return;
	if (strlen(t) + 2 >= outlen) {
		out[0] = 0;
		return;
	}
	snprintf(out, outlen, "%s/", t);
#endif
}

int
zstdio_make_capture_path(const char *which, char *out, size_t outlen)
{
	char dir[ZDBG_STDIO_PATH_MAX];
	int n;

	if (which == NULL || out == NULL || outlen == 0)
		return -1;
	dir[0] = 0;
	zstdio_temp_dir(dir, sizeof(dir));
	zstdio_capture_counter++;
	n = snprintf(out, outlen, "%szdbg-%s-%u-%lu.log",
	    dir, which, ZDBG_GETPID(), zstdio_capture_counter);
	if (n < 0 || (size_t)n >= outlen)
		return -1;
	return 0;
}

void
zstdio_describe(const struct zstdio_slot *s, char *out, size_t outlen)
{
	if (out == NULL || outlen == 0)
		return;
	if (s == NULL) {
		out[0] = 0;
		return;
	}
	switch (s->mode) {
	case ZSTDIO_INHERIT:
		snprintf(out, outlen, "inherit");
		break;
	case ZSTDIO_NULL:
		snprintf(out, outlen, "null");
		break;
	case ZSTDIO_FILE:
		snprintf(out, outlen, "file %s", s->path);
		break;
	case ZSTDIO_CAPTURE:
		snprintf(out, outlen, "capture %s", s->path);
		break;
	case ZSTDIO_STDOUT:
		snprintf(out, outlen, "stdout");
		break;
	default:
		snprintf(out, outlen, "?");
		break;
	}
}

const char *
zstdio_slot_path(const struct zstdio_slot *s)
{
	if (s == NULL)
		return NULL;
	if (s->mode == ZSTDIO_FILE || s->mode == ZSTDIO_CAPTURE)
		return s->path;
	return NULL;
}
