/*
 * main.c - zdbg entry point.
 */

#include <stdio.h>

#include "zdbg.h"
#include "zdbg_cmd.h"

static void
banner(void)
{
	printf("zdbg %d.%d - small DEBUG.COM-inspired debugger (framework)\n"
	    "type ? for help, q to quit\n",
	    ZDBG_VERSION_MAJOR, ZDBG_VERSION_MINOR);
}

int
main(int argc, char **argv)
{
	struct zdbg d;

	banner();
	if (argc > 1)
		printf("target path: %s (not launched - framework only)\n",
		    argv[1]);

	zdbg_init(&d);
	zrepl_run(&d);
	zdbg_fini(&d);
	return 0;
}
