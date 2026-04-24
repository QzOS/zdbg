/*
 * testprog.c - minimal program used as a manual debugger target
 * by later issues.  It is deliberately boring.
 */

#include <stdio.h>

#if defined(_WIN32)
/*
 * Exported, named no-op used for the manual Windows patch
 * persistence test:
 *     sym testprog:zdbg_exported_nop
 *     pa testprog:zdbg_exported_nop 1 int3
 *     pl
 *     pf 0
 *     pw 0
 * The function lives in the PE .text section, so its RVA is
 * backed by raw file bytes and `pw` can rewrite a single byte.
 * The volatile store is there to keep the compiler from
 * collapsing it to a bare `ret`.
 */
__declspec(dllexport) void
zdbg_exported_nop(void)
{
	volatile int x;

	x = 1;
	(void)x;
}
#endif

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

#if defined(_WIN32)
	zdbg_exported_nop();
#endif
	for (i = 0; i < 5; i++) {
		zdbg_watch_value = i;
		foo(i);
	}

	return 0;
}
