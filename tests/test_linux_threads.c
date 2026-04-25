/*
 * test_linux_threads.c - Linux integration test for basic
 * thread awareness: PTRACE_O_TRACECLONE, thread-table growth
 * on clone events, thread_get / select_thread, and best-effort
 * all-stop after a user-visible stop.
 *
 * Launches examples/testthreads (which spawns exactly one
 * worker pthread) under the ptrace backend, continues once so
 * the clone event is observed, then asserts:
 *
 *   - thread_count() transitions from 1 to 2 within a bounded
 *     number of resume/wait rounds
 *   - each thread entry has nonzero TID
 *   - select_thread() accepts both thread TIDs
 *   - current_thread() tracks the selection
 *
 * The test skips cleanly (exit 0) if ptrace is denied, launch
 * is blocked, or the example is not built (ZDBG_TESTTHREADS
 * env var missing or path unreadable).
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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "zdbg_target.h"
#include "zdbg_regs.h"

static int
ptrace_allowed(void)
{
	pid_t child = fork();
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
	}
	return 1;
}

static const char *
find_testthreads(void)
{
	static const char *candidates[] = {
		"./examples/testthreads",
		"./build/examples/testthreads",
		"../examples/testthreads",
		NULL
	};
	const char *env = getenv("ZDBG_TESTTHREADS");
	int i;
	struct stat sb;

	if (env != NULL && stat(env, &sb) == 0)
		return env;
	for (i = 0; candidates[i] != NULL; i++) {
		if (stat(candidates[i], &sb) == 0)
			return candidates[i];
	}
	return NULL;
}

#define SKIP(msg) do { printf("SKIP: %s\n", msg); \
	ztarget_fini(&tgt); return 0; } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); \
	ztarget_kill(&tgt); ztarget_fini(&tgt); return 1; } while (0)

int
main(void)
{
	struct ztarget tgt;
	struct zstop st;
	char *argv[2];
	const char *path;
	int rounds;
	int nthreads;
	uint64_t tids[8];
	int i;

	if (!ptrace_allowed()) {
		printf("SKIP: ptrace not permitted\n");
		return 0;
	}
	path = find_testthreads();
	if (path == NULL) {
		printf("SKIP: testthreads binary not found\n");
		return 0;
	}

	ztarget_init(&tgt);
	argv[0] = (char *)path;
	argv[1] = NULL;
	if (ztarget_launch(&tgt, 1, argv, NULL) < 0) {
		printf("SKIP: launch failed (errno=%d)\n", errno);
		ztarget_fini(&tgt);
		return 0;
	}

	/* Immediately after launch we should have exactly one thread. */
	nthreads = ztarget_thread_count(&tgt);
	if (nthreads < 1)
		FAIL("thread_count < 1 after launch");

	/*
	 * Continue/wait a few rounds giving the target time to
	 * pthread_create.  A clone event arrives on the parent;
	 * the wait path adds the worker to the table and keeps
	 * running internally.  The user-visible stop we see here
	 * is either the worker's eventual SIGSTOP from the all-
	 * stop drain, or the process exiting when the main thread
	 * finishes sleep(2).
	 */
	for (rounds = 0; rounds < 6; rounds++) {
		if (ztarget_continue(&tgt) < 0)
			FAIL("continue failed");
		/*
		 * Short sleep to let the child actually spawn its
		 * worker thread before we (potentially) take the
		 * next stop.  The backend's all-stop drain will
		 * pause the worker once it sees user-visible stop.
		 */
		usleep(400 * 1000);
		/*
		 * Force a stop: send SIGSTOP to the tgid so the
		 * tracer observes a user-visible stop soon.  This
		 * is only to make the test deterministic; in a
		 * real session the user would hit a breakpoint.
		 */
		(void)kill((pid_t)tgt.pid, SIGSTOP);
		memset(&st, 0, sizeof(st));
		if (ztarget_wait(&tgt, &st) < 0)
			FAIL("wait failed");
		if (st.reason == ZSTOP_EXIT)
			break;
		nthreads = ztarget_thread_count(&tgt);
		if (nthreads >= 2)
			break;
	}

	nthreads = ztarget_thread_count(&tgt);
	if (nthreads < 2)
		FAIL("expected >= 2 threads after clone event");

	/* Collect TIDs. */
	for (i = 0; i < nthreads && i < (int)(sizeof(tids) / sizeof(tids[0]));
	    i++) {
		struct zthread th;
		if (ztarget_thread_get(&tgt, i, &th) < 0)
			FAIL("thread_get");
		if (th.tid == 0)
			FAIL("zero tid in table");
		tids[i] = th.tid;
	}

	/* Select each known tid. */
	for (i = 0; i < nthreads && i < (int)(sizeof(tids) / sizeof(tids[0]));
	    i++) {
		if (ztarget_select_thread(&tgt, tids[i]) < 0)
			FAIL("select_thread");
		if (ztarget_current_thread(&tgt) != tids[i])
			FAIL("current_thread mismatch");
	}

	/* Selecting a clearly-unknown TID must fail. */
	if (ztarget_select_thread(&tgt, 1) == 0)
		FAIL("select_thread accepted bogus tid");

	ztarget_kill(&tgt);
	ztarget_fini(&tgt);
	printf("OK\n");
	return 0;
}

#endif /* __linux__ */
