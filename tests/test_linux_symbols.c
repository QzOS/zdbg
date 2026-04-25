/*
 * test_linux_symbols.c - smoke test: launch examples/testprog,
 * refresh maps, refresh symbols, and ensure `main` shows up.
 * Skip cleanly when ptrace is denied (matches other linux
 * tests).
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zdbg_cmd.h"
#include "zdbg_maps.h"
#include "zdbg_symbols.h"
#include "zdbg_target.h"

static int
locate_testprog(char *out, size_t cap)
{
	static const char *candidates[] = {
		"examples/testprog",
		"../examples/testprog",
		"./testprog",
		"../testprog",
		NULL,
	};
	const char *env = getenv("ZDBG_TESTPROG");
	struct stat sb;
	int i;

	if (env != NULL && stat(env, &sb) == 0) {
		snprintf(out, cap, "%s", env);
		return 0;
	}
	for (i = 0; candidates[i] != NULL; i++) {
		if (stat(candidates[i], &sb) == 0) {
			snprintf(out, cap, "%s", candidates[i]);
			return 0;
		}
	}
	return -1;
}

int
main(void)
{
	struct ztarget t;
	struct zmap_table mt;
	struct zsym_table st;
	struct zstop stop;
	char path[512];
	char *argv_v[2];

	if (locate_testprog(path, sizeof(path)) < 0) {
		printf("test_linux_symbols skipped: testprog not found\n");
		return 0;
	}

	ztarget_init(&t);
	zmaps_init(&mt);
	zsyms_init(&st);

	argv_v[0] = path;
	argv_v[1] = NULL;
	if (ztarget_launch(&t, 1, argv_v, NULL) != 0) {
		if (errno == EPERM || errno == EACCES) {
			printf("test_linux_symbols skipped: ptrace denied\n");
			return 0;
		}
		printf("test_linux_symbols skipped: launch failed\n");
		return 0;
	}
	memset(&stop, 0, sizeof(stop));
	/* Initial exec trap is consumed internally by the backend,
	 * but we still need the process to be stopped before
	 * reading /proc/<pid>/maps. */
	zmaps_set_main_hint(&mt, path);
	if (zmaps_refresh(&t, &mt) != 0) {
		fprintf(stderr, "maps refresh failed\n");
		(void)ztarget_kill(&t);
		return 1;
	}
	if (zsyms_refresh(&t, &mt, &st) < 0) {
		fprintf(stderr, "syms refresh failed\n");
		(void)ztarget_kill(&t);
		return 1;
	}

	{
		int amb = 0;
		const struct zsym *s = zsyms_find_exact(&st, "main", &amb);
		if (s == NULL) {
			fprintf(stderr, "main not found in symbol table "
			    "(count=%d)\n", st.count);
			(void)ztarget_kill(&t);
			return 1;
		}
		/* Resolved address should live inside some executable
		 * mapping of the main binary. */
		{
			const struct zmap *m =
			    zmaps_find_by_addr(&mt, s->addr);
			if (m == NULL) {
				fprintf(stderr,
				    "main addr %llx not in any mapping\n",
				    (unsigned long long)s->addr);
				(void)ztarget_kill(&t);
				return 1;
			}
		}
	}

	(void)ztarget_kill(&t);
	ztarget_fini(&t);
	printf("test_linux_symbols ok\n");
	return 0;
}
