/*
 * maps_linux.c - Linux /proc/<pid>/maps reader.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_maps.h"

int
zmaps_refresh(struct ztarget *t, struct zmap_table *mt)
{
	char path[64];
	char line[1024];
	FILE *fp;

	if (mt == NULL)
		return -1;
	mt->count = 0;
	mt->truncated = 0;
	if (t == NULL || t->pid == 0)
		return -1;

	snprintf(path, sizeof(path), "/proc/%llu/maps",
	    (unsigned long long)t->pid);
	fp = fopen(path, "r");
	if (fp == NULL)
		return -1;

	while (fgets(line, sizeof(line), fp) != NULL) {
		struct zmap m;
		if (mt->count >= ZDBG_MAX_MAPS) {
			mt->truncated = 1;
			break;
		}
		if (zmaps_parse_line(line, &m) < 0)
			continue;
		mt->maps[mt->count++] = m;
	}
	fclose(fp);
	return 0;
}

int
zmaps_refresh_regions(struct ztarget *t, struct zmap_table *mt)
{
	/* On Linux /proc/<pid>/maps is already a region view; the
	 * file/anon classification stored in raw_file_offset_valid
	 * and the bracketed names in `name` carry the same
	 * information VirtualQueryEx provides on Windows. */
	return zmaps_refresh(t, mt);
}
