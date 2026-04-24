/*
 * main.c - zdbg entry point.
 *
 * Remaining argv after the program name is remembered on the
 * zdbg state so that a bare `l` at the prompt launches the
 * target that was named on the command line.
 */

#include <stdio.h>

#include "zdbg.h"
#include "zdbg_cmd.h"

static void
banner(void)
{
	printf("zdbg %d.%d - small DEBUG.COM-inspired debugger\n"
	    "type ? for help, q to quit\n",
	    ZDBG_VERSION_MAJOR, ZDBG_VERSION_MINOR);
}

int
main(int argc, char **argv)
{
	struct zdbg d;

	banner();
	zdbg_init(&d);
	if (argc > 1) {
		d.target_argc = argc - 1;
		d.target_argv = argv + 1;
		printf("target: %s (type `l` to launch)\n", argv[1]);
	}
	zrepl_run(&d);
	zdbg_fini(&d);
	return 0;
}
