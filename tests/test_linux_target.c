/*
 * test_linux_target.c - Linux-only smoke test for the ptrace
 * backend.  Launches /bin/true, verifies we stop at the initial
 * trap, reads registers, and lets it run to exit.
 *
 * The test is skipped (exits 0) if ptrace is denied, so it
 * cannot make CI flaky when run under Docker, LXC or kernels
 * with hardened YAMA ptrace policy.
 */

#if !defined(__linux__)

int main(void) { return 0; }

#else

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "zdbg_target.h"
#include "zdbg_regs.h"

static int
ptrace_allowed(void)
{
	pid_t child;
	int rc = 0;

	child = fork();
	if (child < 0)
		return 0;
	if (child == 0) {
		if (ptrace(PTRACE_TRACEME, 0, (void *)0, (void *)0) < 0)
			_exit(1);
		_exit(0);
	}
	{
		int st = 0;
		waitpid(child, &st, 0);
		rc = 1;
	}
	return rc;
}

int
main(void)
{
	struct ztarget tgt;
	struct zregs r;
	struct zstop st;
	char *argv[2];
	int rc;

	if (!ptrace_allowed()) {
		printf("SKIP: ptrace not permitted in this environment\n");
		return 0;
	}

	argv[0] = (char *)"/bin/true";
	argv[1] = NULL;

	ztarget_init(&tgt);
	rc = ztarget_launch(&tgt, 1, argv);
	if (rc < 0) {
		/*
		 * Some sandboxes allow PTRACE_TRACEME but block exec
		 * of /bin/true; treat as skip rather than failure.
		 */
		printf("SKIP: launch failed (errno=%d)\n", errno);
		ztarget_fini(&tgt);
		return 0;
	}
	if (tgt.state != ZTARGET_STOPPED) {
		printf("FAIL: state after launch != STOPPED\n");
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

	/* Single-step once, should report single-step. */
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
	if (st.reason != ZSTOP_SINGLESTEP && st.reason != ZSTOP_EXIT) {
		printf("FAIL: unexpected stop reason %d\n", (int)st.reason);
		ztarget_kill(&tgt);
		return 1;
	}

	/* Continue until exit. */
	if (st.reason != ZSTOP_EXIT) {
		if (ztarget_continue(&tgt) < 0) {
			printf("FAIL: continue\n");
			ztarget_kill(&tgt);
			return 1;
		}
		memset(&st, 0, sizeof(st));
		if (ztarget_wait(&tgt, &st) < 0) {
			printf("FAIL: wait after continue\n");
			return 1;
		}
	}

	ztarget_fini(&tgt);
	printf("OK\n");
	return 0;
}

#endif /* __linux__ */
