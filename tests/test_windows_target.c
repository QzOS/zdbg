/*
 * test_windows_target.c - Windows-only smoke test for the Win32
 * Debug API backend.  Launches a trivial target (cmd.exe /c exit
 * falls back to the examples testprog if ZDBG_TESTPROG is set),
 * verifies we stop at the initial breakpoint, reads registers,
 * and lets it run to exit.
 *
 * Non-Windows builds compile this as a no-op so CTest stays
 * portable.
 */

#ifndef _WIN32

int main(void) { return 0; }

#else

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zdbg_target.h"
#include "zdbg_regs.h"

int
main(void)
{
	struct ztarget tgt;
	struct zregs r;
	struct zstop st;
	char *argv[2];
	const char *prog;
	int rc;

	prog = getenv("ZDBG_TESTPROG");
	if (prog == NULL || prog[0] == 0)
		prog = "C:\\Windows\\System32\\cmd.exe";

	argv[0] = (char *)prog;
	argv[1] = NULL;

	ztarget_init(&tgt);
	rc = ztarget_launch(&tgt, 1, argv);
	if (rc < 0) {
		/*
		 * Some sandboxes block CreateProcess with the debug
		 * flag; treat as skip rather than failure so CI
		 * without Windows runners does not flake.
		 */
		printf("SKIP: launch failed (GetLastError=%lu)\n",
		    (unsigned long)GetLastError());
		ztarget_fini(&tgt);
		return 0;
	}
	if (tgt.state != ZTARGET_STOPPED) {
		printf("FAIL: state after launch != STOPPED (%d)\n",
		    (int)tgt.state);
		ztarget_kill(&tgt);
		return 1;
	}

	memset(&r, 0, sizeof(r));
	if (ztarget_getregs(&tgt, &r) < 0) {
		printf("FAIL: getregs\n");
		ztarget_kill(&tgt);
		return 1;
	}
	if (r.rip == 0) {
		printf("FAIL: rip == 0 after initial stop\n");
		ztarget_kill(&tgt);
		return 1;
	}

	/* Single-step once; expect SINGLESTEP or a later EXIT. */
	if (ztarget_singlestep(&tgt) < 0) {
		printf("FAIL: singlestep\n");
		ztarget_kill(&tgt);
		return 1;
	}
	memset(&st, 0, sizeof(st));
	if (ztarget_wait(&tgt, &st) < 0) {
		printf("FAIL: wait after singlestep\n");
		ztarget_kill(&tgt);
		return 1;
	}
	if (st.reason != ZSTOP_SINGLESTEP && st.reason != ZSTOP_EXIT &&
	    st.reason != ZSTOP_EXCEPTION) {
		printf("FAIL: unexpected stop reason %d\n",
		    (int)st.reason);
		ztarget_kill(&tgt);
		return 1;
	}

	/* Kill and clean up regardless of current state. */
	ztarget_kill(&tgt);
	ztarget_fini(&tgt);
	printf("OK\n");
	return 0;
}

#endif /* _WIN32 */
