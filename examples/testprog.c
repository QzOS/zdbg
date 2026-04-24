/*
 * testprog.c - minimal program used as a manual debugger target
 * by later issues.  It is deliberately boring.
 */

#include <stdio.h>

/*
 * zdbg_watch_value is a globally visible write target for the
 * manual hardware watchpoint test:
 *     sym zdbg_watch_value
 *     hw zdbg_watch_value 4 w
 *     g
 * The variable is volatile and aligned to 4 bytes so it is a
 * legal data watchpoint target.
 */
volatile int zdbg_watch_value;

static void
foo(int x)
{
	printf("foo %d\n", x);
}

int
main(void)
{
	int i;

	for (i = 0; i < 5; i++) {
		zdbg_watch_value = i;
		foo(i);
	}

	return 0;
}
