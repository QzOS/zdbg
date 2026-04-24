/*
 * testprog.c - minimal program used as a manual debugger target
 * by later issues.  It is deliberately boring.
 */

#include <stdio.h>

static void
foo(int x)
{
	printf("foo %d\n", x);
}

int
main(void)
{
	int i;

	for (i = 0; i < 5; i++)
		foo(i);

	return 0;
}
