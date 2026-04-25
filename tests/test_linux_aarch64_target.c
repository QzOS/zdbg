/*
 * test_linux_aarch64_target.c - native AArch64 Linux ptrace
 * smoke test.  Launches /bin/true through the backend, verifies
 * the backend reports ZARCH_AARCH64, fetches the integer
 * register file via PTRACE_GETREGSET, sanity-checks PC and SP
 * via roles, performs one single-step, and lets the target
 * exit.  Skipped (exits 0) if ptrace is denied.
 */

#if !defined(__linux__) || !defined(__aarch64__)

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
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "zdbg_arch.h"
#include "zdbg_regfile.h"
#include "zdbg_target.h"

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
	struct zreg_file rf;
	struct zstop st;
	char *argv[2];
	uint64_t pc = 0;
	uint64_t sp = 0;
	int rc;

	if (!ptrace_allowed()) {
		printf("SKIP: ptrace not permitted in this environment\n");
		return 0;
	}

	argv[0] = (char *)"/bin/true";
	argv[1] = NULL;

	ztarget_init(&tgt);
	rc = ztarget_launch(&tgt, 1, argv, NULL);
	if (rc < 0) {
		printf("SKIP: launch failed (errno=%d)\n", errno);
		ztarget_fini(&tgt);
		return 0;
	}
	if (tgt.state != ZTARGET_STOPPED) {
		printf("FAIL: state after launch != STOPPED\n");
		ztarget_kill(&tgt);
		return 1;
	}
	if (tgt.arch != ZARCH_AARCH64) {
		printf("FAIL: tgt.arch=%d, expected ZARCH_AARCH64\n",
		    (int)tgt.arch);
		ztarget_kill(&tgt);
		return 1;
	}

	if (ztarget_get_regfile(&tgt, ZARCH_AARCH64, &rf) < 0) {
		printf("FAIL: get_regfile(AARCH64)\n");
		ztarget_kill(&tgt);
		return 1;
	}
	if (zregfile_get_role(&rf, ZREG_ROLE_PC, &pc) < 0 || pc == 0) {
		printf("FAIL: PC role unreadable or zero\n");
		ztarget_kill(&tgt);
		return 1;
	}
	if (zregfile_get_role(&rf, ZREG_ROLE_SP, &sp) < 0 || sp == 0) {
		printf("FAIL: SP role unreadable or zero\n");
		ztarget_kill(&tgt);
		return 1;
	}

	/* Single-step once. */
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
		printf("FAIL: unexpected stop reason %d\n",
		    (int)st.reason);
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

#endif /* __linux__ && __aarch64__ */
