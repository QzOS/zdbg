/*
 * maps.c - host-independent memory map table.
 *
 * Parsing of a single /proc/<pid>/maps line lives here so it can
 * be unit tested without a live target.  Live /proc reading is
 * in src/os_linux/maps_linux.c.  On non-Linux hosts the refresh
 * returns -1 and leaves the table empty.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "zdbg_maps.h"

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

static const char *
parse_hex64(const char *p, zaddr_t *out)
{
	zaddr_t v = 0;
	int digits = 0;
	int h;

	while ((h = hexval((unsigned char)*p)) >= 0) {
		v = (v << 4) | (zaddr_t)h;
		p++;
		digits++;
	}
	if (digits == 0)
		return NULL;
	*out = v;
	return p;
}

static const char *
skip_ws(const char *p)
{
	while (*p == ' ' || *p == '\t')
		p++;
	return p;
}

static const char *
skip_nonws(const char *p)
{
	while (*p && *p != ' ' && *p != '\t' && *p != '\n')
		p++;
	return p;
}

static const char *
basename_of(const char *path)
{
	const char *p;
	const char *last = path;

	if (path == NULL)
		return NULL;
	for (p = path; *p; p++) {
		if (*p == '/')
			last = p + 1;
	}
	return last;
}

void
zmaps_init(struct zmap_table *mt)
{
	if (mt == NULL)
		return;
	memset(mt, 0, sizeof(*mt));
}

void
zmaps_set_main_hint(struct zmap_table *mt, const char *path)
{
	size_t n;

	if (mt == NULL)
		return;
	if (path == NULL) {
		mt->main_hint[0] = 0;
		return;
	}
	n = strlen(path);
	if (n >= sizeof(mt->main_hint))
		n = sizeof(mt->main_hint) - 1;
	memcpy(mt->main_hint, path, n);
	mt->main_hint[n] = 0;
}

int
zmaps_parse_line(const char *line, struct zmap *m)
{
	const char *p;
	zaddr_t start = 0;
	zaddr_t end = 0;
	zaddr_t off = 0;
	int i;
	size_t n;

	if (line == NULL || m == NULL)
		return -1;
	memset(m, 0, sizeof(*m));

	p = skip_ws(line);
	p = parse_hex64(p, &start);
	if (p == NULL || *p != '-')
		return -1;
	p++;
	p = parse_hex64(p, &end);
	if (p == NULL)
		return -1;

	p = skip_ws(p);
	/* permissions: exactly 4 chars */
	for (i = 0; i < 4; i++) {
		if (p[i] == 0 || p[i] == '\n' || p[i] == ' ' || p[i] == '\t')
			return -1;
		m->perms[i] = p[i];
	}
	m->perms[4] = 0;
	p += 4;

	p = skip_ws(p);
	p = parse_hex64(p, &off);
	if (p == NULL)
		return -1;

	/* dev (hex:hex) - skip token */
	p = skip_ws(p);
	p = skip_nonws(p);

	/* inode - skip token */
	p = skip_ws(p);
	p = skip_nonws(p);

	/* remainder after optional whitespace is the name (may
	 * include spaces).  Strip trailing newline and whitespace.
	 */
	p = skip_ws(p);
	n = strlen(p);
	while (n > 0 && (p[n - 1] == '\n' || p[n - 1] == '\r'))
		n--;
	if (n >= sizeof(m->name))
		n = sizeof(m->name) - 1;
	memcpy(m->name, p, n);
	m->name[n] = 0;

	m->start = start;
	m->end = end;
	m->offset = off;
	return 0;
}

void
zmaps_print_one(int idx, const struct zmap *m)
{
	if (m == NULL)
		return;
	printf("%3d %016llx-%016llx %4s off=%08llx %s\n",
	    idx,
	    (unsigned long long)m->start,
	    (unsigned long long)m->end,
	    m->perms,
	    (unsigned long long)m->offset,
	    m->name);
}

void
zmaps_print(const struct zmap_table *mt)
{
	int i;

	if (mt == NULL)
		return;
	for (i = 0; i < mt->count; i++)
		zmaps_print_one(i, &mt->maps[i]);
	if (mt->truncated)
		printf("(truncated at %d maps)\n", ZDBG_MAX_MAPS);
}

const struct zmap *
zmaps_find_by_addr(const struct zmap_table *mt, zaddr_t addr)
{
	int i;

	if (mt == NULL)
		return NULL;
	for (i = 0; i < mt->count; i++) {
		const struct zmap *m = &mt->maps[i];
		if (addr >= m->start && addr < m->end)
			return m;
	}
	return NULL;
}

static int
has_exec(const struct zmap *m)
{
	return strchr(m->perms, 'x') != NULL;
}

static int
is_bracketed(const char *name)
{
	size_t n;

	if (name == NULL || name[0] != '[')
		return 0;
	n = strlen(name);
	return n > 0 && name[n - 1] == ']';
}

/*
 * Pick the "main" executable mapping.  Preference order:
 *   1. exact main_hint match, executable
 *   2. exact main_hint match, any perms
 *   3. basename(main_hint) match, executable
 *   4. first file-backed executable mapping
 *   5. first file-backed mapping
 */
static const struct zmap *
find_main(const struct zmap_table *mt)
{
	const struct zmap *first_file = NULL;
	const struct zmap *first_file_x = NULL;
	const struct zmap *hint_any = NULL;
	const struct zmap *hint_x = NULL;
	const struct zmap *base_x = NULL;
	const char *hint_base = NULL;
	int i;

	if (mt->main_hint[0])
		hint_base = basename_of(mt->main_hint);

	for (i = 0; i < mt->count; i++) {
		const struct zmap *m = &mt->maps[i];
		if (m->name[0] == 0 || is_bracketed(m->name))
			continue;
		if (first_file == NULL)
			first_file = m;
		if (has_exec(m) && first_file_x == NULL)
			first_file_x = m;
		if (mt->main_hint[0] &&
		    strcmp(m->name, mt->main_hint) == 0) {
			if (hint_any == NULL)
				hint_any = m;
			if (has_exec(m) && hint_x == NULL)
				hint_x = m;
		} else if (hint_base != NULL &&
		    strcmp(basename_of(m->name), hint_base) == 0) {
			if (has_exec(m) && base_x == NULL)
				base_x = m;
		}
	}
	if (hint_x)
		return hint_x;
	if (hint_any)
		return hint_any;
	if (base_x)
		return base_x;
	if (first_file_x)
		return first_file_x;
	return first_file;
}

/*
 * Starts-with check for a basename prefix match.  We require
 * that the rest of the basename begins with a non-alnum
 * boundary like '.' or '-' to avoid "lib" matching "libc" and
 * "liburing" both.  Callers still handle ambiguity.
 */
static int
basename_prefix_match(const char *base, const char *query)
{
	size_t qn = strlen(query);
	char sep;

	if (strncmp(base, query, qn) != 0)
		return 0;
	sep = base[qn];
	if (sep == 0)
		return 1;
	if (sep == '.' || sep == '-' || sep == '_')
		return 1;
	return 0;
}

const struct zmap *
zmaps_find_module(const struct zmap_table *mt, const char *name,
    int *ambiguous)
{
	const struct zmap *exact_path_x = NULL;
	const struct zmap *exact_path_any = NULL;
	const struct zmap *exact_base_x = NULL;
	const struct zmap *exact_base_any = NULL;
	const struct zmap *prefix_x = NULL;
	const struct zmap *prefix_any = NULL;
	int prefix_count_x = 0;
	int prefix_count_any = 0;
	int i;

	if (ambiguous)
		*ambiguous = 0;
	if (mt == NULL || name == NULL || *name == 0)
		return NULL;

	if (strcmp(name, "main") == 0)
		return find_main(mt);

	/* map:N */
	if (strncmp(name, "map:", 4) == 0) {
		const char *p = name + 4;
		int idx = 0;
		int digits = 0;
		while (*p >= '0' && *p <= '9') {
			idx = idx * 10 + (*p - '0');
			p++;
			digits++;
			if (idx >= ZDBG_MAX_MAPS || digits > 9)
				return NULL;
		}
		if (digits == 0 || *p != 0)
			return NULL;
		if (idx < 0 || idx >= mt->count)
			return NULL;
		return &mt->maps[idx];
	}

	for (i = 0; i < mt->count; i++) {
		const struct zmap *m = &mt->maps[i];
		const char *b;

		if (m->name[0] == 0)
			continue;

		/* exact full path or bracketed name */
		if (strcmp(m->name, name) == 0) {
			if (has_exec(m)) {
				if (exact_path_x == NULL)
					exact_path_x = m;
			} else {
				if (exact_path_any == NULL)
					exact_path_any = m;
			}
			continue;
		}

		/* bracketed names don't participate in basename
		 * matching
		 */
		if (is_bracketed(m->name))
			continue;

		b = basename_of(m->name);
		if (strcmp(b, name) == 0) {
			if (has_exec(m)) {
				if (exact_base_x == NULL)
					exact_base_x = m;
			} else {
				if (exact_base_any == NULL)
					exact_base_any = m;
			}
			continue;
		}
		if (basename_prefix_match(b, name)) {
			if (has_exec(m)) {
				if (prefix_x == NULL ||
				    strcmp(basename_of(prefix_x->name), b)
				    != 0) {
					prefix_count_x++;
					if (prefix_x == NULL)
						prefix_x = m;
				}
			} else {
				if (prefix_any == NULL ||
				    strcmp(basename_of(prefix_any->name), b)
				    != 0) {
					prefix_count_any++;
					if (prefix_any == NULL)
						prefix_any = m;
				}
			}
		}
	}

	if (exact_path_x)
		return exact_path_x;
	if (exact_path_any)
		return exact_path_any;
	if (exact_base_x)
		return exact_base_x;
	if (exact_base_any)
		return exact_base_any;
	if (prefix_count_x == 1)
		return prefix_x;
	if (prefix_count_x > 1) {
		if (ambiguous)
			*ambiguous = 1;
		return NULL;
	}
	if (prefix_count_any == 1)
		return prefix_any;
	if (prefix_count_any > 1) {
		if (ambiguous)
			*ambiguous = 1;
		return NULL;
	}
	return NULL;
}

int
zmaps_resolve(const struct zmap_table *mt, const char *name,
    zaddr_t off, zaddr_t *out)
{
	const struct zmap *m;
	int amb = 0;

	if (mt == NULL || name == NULL || out == NULL)
		return -1;
	m = zmaps_find_module(mt, name, &amb);
	if (m == NULL) {
		if (amb)
			return -2;
		return -1;
	}
	*out = m->start + off;
	return 0;
}

#if !defined(__linux__)
int
zmaps_refresh(struct ztarget *t, struct zmap_table *mt)
{
	(void)t;
	if (mt != NULL)
		mt->count = 0;
	return -1;
}
#endif
