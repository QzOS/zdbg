/*
 * repl.c - line-oriented read/eval/print loop.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_cmd.h"

int
zrepl_run(struct zdbg *d)
{
	char line[512];

	if (d == NULL)
		return -1;

	for (;;) {
		int rc;
		size_t n;

		printf("- ");
		fflush(stdout);
		if (fgets(line, sizeof(line), stdin) == NULL) {
			printf("\n");
			break;
		}
		n = strlen(line);
		while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
			line[--n] = 0;

		rc = zcmd_exec(d, line);
		if (rc == 1) /* RC_QUIT */
			break;
	}
	return 0;
}
