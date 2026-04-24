/*
 * target_linux.c - Linux ptrace backend.
 *
 * Implements launch, attach (including attach-to-all-existing-
 * threads), detach, kill, wait, continue, single-step, memory
 * read/write, and register get/set on top of ptrace() for x86-64.
 *
 * Linux thread awareness
 * ----------------------
 * The backend keeps a fixed-size table of traced threads
 * (tasks).  Launch starts with the initial task; attach
 * enumerates /proc/<tgid>/task and ATTACHes to every visible
 * TID.  New clone()d tasks are discovered via
 * PTRACE_EVENT_CLONE and added to the table automatically.
 *
 * waitpid(-1, ..., __WALL) is used so events from any traced
 * thread are observed.  ztarget_linux_wait() swallows internal
 * events (clone, new-thread SIGSTOP at initial attach) and only
 * returns for user-visible stops.  When one thread stops for a
 * user-visible reason, the backend makes a best-effort attempt
 * to stop every other running traced thread (tgkill SIGSTOP +
 * drain) so that zdbg stays all-stop at the prompt.
 *
 * ztarget_linux_continue() continues all stopped non-exited
 * threads; ztarget_linux_singlestep() steps only the selected
 * thread.  Memory and register access operate on the currently
 * selected thread (TID in ztarget.tid).  The debug register
 * helpers also have a _all variant that programs DR0..DR7 into
 * every known traced thread, which is how hardware breakpoints
 * and watchpoints become meaningful in multi-threaded targets.
 *
 * All of this is intentionally first-pass, best-effort.  In
 * particular the all-stop drain may race with brand-new clone
 * children and software-breakpoint rearm is still not fully
 * race-free under heavy multi-threaded loads.  See the README
 * for the documented limitations.
 *
 * Launch contract
 * ---------------
 * ztarget_linux_launch() performs the initial waitpid() for the
 * exec trap internally and returns with the target stopped
 * (state == ZTARGET_STOPPED).  The first SIGTRAP after exec is
 * normalized to ZSTOP_INITIAL.
 */

#if defined(__linux__)

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__x86_64__)
#include <sys/user.h>
#endif

#include "zdbg_target.h"
#include "zdbg_signal.h"

#ifndef __WALL
#define __WALL 0x40000000
#endif

/*
 * PTRACE_EVENT_CLONE is declared in <sys/ptrace.h> on Linux.
 * Define a fallback constant for the extremely unlikely case
 * of building against an ancient libc where the header omits
 * it; the kernel ABI is stable.
 */
#ifndef PTRACE_EVENT_CLONE
#define PTRACE_EVENT_CLONE 3
#endif

#define ZL_MAX_THREADS ZDBG_MAX_THREADS

struct zlinux_thread {
	pid_t tid;
	int stopped;
	int exited;
	int exit_code;
	int options_set;
	int last_signal;	/* signal to redeliver on next resume */
};

struct zlinux_target {
	pid_t tgid;		/* process id (TGID) */
	pid_t current_tid;	/* selected thread */
	int attached;
	int launched;
	int exited;		/* whole process gone */
	int exit_code;
	int singlestep_tid;	/* nonzero while SINGLESTEP is pending */
	struct zlinux_thread threads[ZL_MAX_THREADS];
	int nthreads;		/* number of nonempty slots (high-water) */
};

static struct zlinux_target *
zl_get(struct ztarget *t)
{
	if (t == NULL)
		return NULL;
	return (struct zlinux_target *)t->os;
}

static struct zlinux_target *
zl_alloc(struct ztarget *t)
{
	struct zlinux_target *lt;

	lt = (struct zlinux_target *)calloc(1, sizeof(*lt));
	if (lt == NULL)
		return NULL;
	t->os = lt;
	return lt;
}

static void
zl_free(struct ztarget *t)
{
	if (t == NULL || t->os == NULL)
		return;
	free(t->os);
	t->os = NULL;
}

/* ---------------- thread table helpers ---------------- */

static struct zlinux_thread *
zl_find(struct zlinux_target *lt, pid_t tid)
{
	int i;

	for (i = 0; i < lt->nthreads; i++) {
		if (lt->threads[i].tid == tid &&
		    !lt->threads[i].exited)
			return &lt->threads[i];
	}
	return NULL;
}

static struct zlinux_thread *
zl_find_any(struct zlinux_target *lt, pid_t tid)
{
	int i;

	for (i = 0; i < lt->nthreads; i++) {
		if (lt->threads[i].tid == tid)
			return &lt->threads[i];
	}
	return NULL;
}

static struct zlinux_thread *
zl_add(struct zlinux_target *lt, pid_t tid)
{
	struct zlinux_thread *th;
	int i;

	th = zl_find_any(lt, tid);
	if (th != NULL)
		return th;
	/* reuse empty slot first */
	for (i = 0; i < lt->nthreads; i++) {
		if (lt->threads[i].tid == 0) {
			th = &lt->threads[i];
			memset(th, 0, sizeof(*th));
			th->tid = tid;
			return th;
		}
	}
	if (lt->nthreads >= ZL_MAX_THREADS)
		return NULL;
	th = &lt->threads[lt->nthreads++];
	memset(th, 0, sizeof(*th));
	th->tid = tid;
	return th;
}

static int
zl_live_count(struct zlinux_target *lt)
{
	int i;
	int n = 0;

	for (i = 0; i < lt->nthreads; i++) {
		if (lt->threads[i].tid != 0 && !lt->threads[i].exited)
			n++;
	}
	return n;
}

/* Set common ptrace options on a traced tid.  Best-effort. */
static void
zl_set_options(struct zlinux_thread *th)
{
	long opts;

	if (th == NULL || th->options_set)
		return;
	opts = PTRACE_O_TRACECLONE;
#ifdef PTRACE_O_EXITKILL
	opts |= PTRACE_O_EXITKILL;
#endif
	if (ptrace(PTRACE_SETOPTIONS, th->tid, (void *)0,
	    (void *)opts) == 0)
		th->options_set = 1;
}

/*
 * Consume any pending zombie for a traced tid without blocking.
 * Used from kill/detach cleanup paths.
 */
static void
zl_reap_nohang(pid_t tid)
{
	int status;
	(void)waitpid(tid, &status, WNOHANG | __WALL);
}

/* ---------------- attach-to-all helpers ---------------- */

static int
zl_is_all_digits(const char *s)
{
	if (s == NULL || *s == 0)
		return 0;
	while (*s) {
		if (!isdigit((unsigned char)*s))
			return 0;
		s++;
	}
	return 1;
}

/*
 * Enumerate numeric entries in /proc/<tgid>/task into out[].
 * Returns the number of TIDs written (up to max).  On error
 * returns 0.
 */
static int
zl_list_tasks(pid_t tgid, pid_t *out, int max)
{
	char path[64];
	DIR *dp;
	struct dirent *de;
	int n = 0;

	snprintf(path, sizeof(path), "/proc/%d/task", (int)tgid);
	dp = opendir(path);
	if (dp == NULL)
		return 0;
	while ((de = readdir(dp)) != NULL && n < max) {
		const char *s = de->d_name;
		long v;
		char *end = NULL;

		if (!zl_is_all_digits(s))
			continue;
		v = strtol(s, &end, 10);
		if (end == s || v <= 0 || v > 0x7fffffff)
			continue;
		out[n++] = (pid_t)v;
	}
	closedir(dp);
	return n;
}

/*
 * Rescan /proc/<tgid>/task and attach to any TIDs we do not
 * already track.  Returns the number of new TIDs attached.
 * Races are expected: TIDs can vanish mid-scan, handle gracefully.
 */
static int
zl_attach_new_tasks(struct zlinux_target *lt)
{
	pid_t tids[ZL_MAX_THREADS];
	int n;
	int i;
	int attached = 0;

	n = zl_list_tasks(lt->tgid, tids, ZL_MAX_THREADS);
	for (i = 0; i < n; i++) {
		pid_t tid = tids[i];
		struct zlinux_thread *th;
		int status;
		pid_t r;

		if (zl_find_any(lt, tid) != NULL)
			continue;
		if (ptrace(PTRACE_ATTACH, tid, (void *)0, (void *)0) < 0) {
			/* ESRCH: task gone, just skip */
			continue;
		}
		do {
			r = waitpid(tid, &status, __WALL);
		} while (r < 0 && errno == EINTR);
		if (r < 0) {
			(void)ptrace(PTRACE_DETACH, tid, (void *)0,
			    (void *)0);
			continue;
		}
		if (WIFEXITED(status) || WIFSIGNALED(status))
			continue;
		if (!WIFSTOPPED(status)) {
			(void)ptrace(PTRACE_DETACH, tid, (void *)0,
			    (void *)0);
			continue;
		}
		th = zl_add(lt, tid);
		if (th == NULL) {
			/* table full: detach rather than leave it hanging */
			(void)ptrace(PTRACE_DETACH, tid, (void *)0,
			    (void *)0);
			continue;
		}
		th->stopped = 1;
		zl_set_options(th);
		attached++;
	}
	return attached;
}

/* ---------------- launch / attach / detach / kill ---------------- */

int
ztarget_linux_launch(struct ztarget *t, int argc, char **argv)
{
	struct zlinux_target *lt;
	struct zlinux_thread *th;
	pid_t pid;
	int status;

	if (t == NULL || argc <= 0 || argv == NULL || argv[0] == NULL)
		return -1;
	if (t->state != ZTARGET_EMPTY)
		return -1;

	lt = zl_alloc(t);
	if (lt == NULL)
		return -1;

	pid = fork();
	if (pid < 0) {
		zl_free(t);
		return -1;
	}
	if (pid == 0) {
		/* Child: enable tracing and exec the target. */
		if (ptrace(PTRACE_TRACEME, 0, (void *)0, (void *)0) < 0)
			_exit(127);
		execvp(argv[0], argv);
		_exit(127);
	}

	/* Parent: wait for the initial exec-trap stop. */
	if (waitpid(pid, &status, 0) < 0) {
		(void)kill(pid, SIGKILL);
		zl_reap_nohang(pid);
		zl_free(t);
		return -1;
	}
	if (WIFEXITED(status) || WIFSIGNALED(status)) {
		zl_free(t);
		return -1;
	}
	if (!WIFSTOPPED(status)) {
		(void)kill(pid, SIGKILL);
		zl_reap_nohang(pid);
		zl_free(t);
		return -1;
	}

	lt->tgid = pid;
	lt->current_tid = pid;
	lt->launched = 1;
	lt->attached = 0;
	lt->singlestep_tid = 0;
	lt->exited = 0;
	lt->exit_code = 0;
	lt->nthreads = 0;

	th = zl_add(lt, pid);
	if (th == NULL) {
		(void)kill(pid, SIGKILL);
		zl_reap_nohang(pid);
		zl_free(t);
		return -1;
	}
	th->stopped = 1;
	zl_set_options(th);

	t->pid = (uint64_t)pid;
	t->tid = (uint64_t)pid;
	t->arch = ZARCH_X86_64;
	t->state = ZTARGET_STOPPED;
	return 0;
}

int
ztarget_linux_attach(struct ztarget *t, uint64_t pid)
{
	struct zlinux_target *lt;
	struct zlinux_thread *th;
	pid_t p;
	int nattached;

	if (t == NULL || pid == 0 || pid > 0x7fffffffULL)
		return -1;
	if (t->state != ZTARGET_EMPTY)
		return -1;
	p = (pid_t)pid;

	lt = zl_alloc(t);
	if (lt == NULL)
		return -1;
	lt->tgid = p;

	nattached = zl_attach_new_tasks(lt);
	if (nattached <= 0) {
		zl_free(t);
		return -1;
	}

	/* Prefer the main thread (tid == tgid) if present. */
	th = zl_find(lt, p);
	if (th == NULL) {
		/* fall back to the first live thread */
		int i;
		for (i = 0; i < lt->nthreads; i++) {
			if (lt->threads[i].tid != 0 && !lt->threads[i].exited) {
				th = &lt->threads[i];
				break;
			}
		}
	}
	if (th == NULL) {
		zl_free(t);
		return -1;
	}

	lt->current_tid = th->tid;
	lt->attached = 1;
	lt->launched = 0;
	lt->singlestep_tid = 0;
	lt->exited = 0;
	lt->exit_code = 0;

	t->pid = (uint64_t)p;
	t->tid = (uint64_t)th->tid;
	t->arch = ZARCH_X86_64;
	t->state = ZTARGET_STOPPED;
	return 0;
}

int
ztarget_linux_detach(struct ztarget *t)
{
	struct zlinux_target *lt = zl_get(t);
	int i;

	if (lt == NULL)
		return -1;
	if (!lt->exited) {
		for (i = 0; i < lt->nthreads; i++) {
			struct zlinux_thread *th = &lt->threads[i];
			if (th->tid == 0 || th->exited)
				continue;
			if (ptrace(PTRACE_DETACH, th->tid, (void *)0,
			    (void *)0) < 0) {
				zl_reap_nohang(th->tid);
			}
		}
	}
	t->state = ZTARGET_DETACHED;
	zl_free(t);
	return 0;
}

int
ztarget_linux_kill(struct ztarget *t)
{
	struct zlinux_target *lt = zl_get(t);
	int status;
	int i;

	if (lt == NULL)
		return -1;
	if (!lt->exited) {
		/*
		 * Detach every traced thread first (with SIGKILL
		 * delivery when the thread is currently stopped).
		 * Detached threads then actually run to receive the
		 * process-wide SIGKILL we send right after.  Without
		 * the detach step a ptrace-stopped thread can sit
		 * indefinitely waiting for the tracer.
		 */
		for (i = 0; i < lt->nthreads; i++) {
			struct zlinux_thread *th = &lt->threads[i];
			if (th->tid == 0 || th->exited)
				continue;
			(void)ptrace(PTRACE_DETACH, th->tid, (void *)0,
			    (void *)(long)SIGKILL);
			th->stopped = 0;
		}
		(void)kill(lt->tgid, SIGKILL);
		/*
		 * Reap every traced task.  After PTRACE_DETACH the
		 * tracer is no longer the parent for sibling
		 * threads, so waitpid may fail with ECHILD for them;
		 * that's fine.
		 */
		for (i = 0; i < lt->nthreads; i++) {
			struct zlinux_thread *th = &lt->threads[i];
			if (th->tid == 0 || th->exited)
				continue;
			for (;;) {
				pid_t r = waitpid(th->tid, &status, __WALL);
				if (r < 0) {
					if (errno == EINTR)
						continue;
					break;
				}
				if (WIFEXITED(status) || WIFSIGNALED(status))
					break;
			}
		}
	}
	t->state = ZTARGET_EXITED;
	zl_free(t);
	return 0;
}

/* ---------------- wait / continue / single-step ---------------- */

static void
zl_mark_exited(struct zlinux_target *lt, pid_t tid, int code)
{
	struct zlinux_thread *th = zl_find_any(lt, tid);
	if (th == NULL)
		return;
	th->exited = 1;
	th->exit_code = code;
	th->stopped = 0;
}

/*
 * Best-effort all-stop: tgkill SIGSTOP every running thread and
 * drain their stops.  Preserves unrelated stop events (clone,
 * real breakpoints, signals) by recording them on the thread
 * entry so they can be redelivered on resume.  Swallows the
 * injected SIGSTOP cleanly.
 */
static void
zl_stop_all_except(struct zlinux_target *lt, pid_t keep_tid)
{
	int i;

	for (i = 0; i < lt->nthreads; i++) {
		struct zlinux_thread *th = &lt->threads[i];
		if (th->tid == 0 || th->exited || th->stopped)
			continue;
		if (th->tid == keep_tid)
			continue;
		(void)syscall(SYS_tgkill, (long)lt->tgid, (long)th->tid,
		    (long)SIGSTOP);
	}
	for (i = 0; i < lt->nthreads; i++) {
		struct zlinux_thread *th = &lt->threads[i];
		int status;
		pid_t r;

		if (th->tid == 0 || th->exited || th->stopped)
			continue;
		if (th->tid == keep_tid)
			continue;
		do {
			r = waitpid(th->tid, &status, __WALL);
		} while (r < 0 && errno == EINTR);
		if (r < 0) {
			/* ESRCH: thread gone */
			th->exited = 1;
			continue;
		}
		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			th->exited = 1;
			th->exit_code = WIFEXITED(status) ?
			    WEXITSTATUS(status) : WTERMSIG(status);
			continue;
		}
		if (WIFSTOPPED(status)) {
			int sig = WSTOPSIG(status);
			int event = (status >> 16) & 0xffff;

			th->stopped = 1;
			zl_set_options(th);
			/* Our injected SIGSTOP is swallowed. */
			if (sig == SIGSTOP)
				th->last_signal = 0;
			else if (sig == SIGTRAP && event != 0)
				th->last_signal = 0;
			else if (sig == SIGTRAP)
				/*
				 * Real trap from this thread; do not
				 * redeliver (kernel already consumed
				 * it via ptrace).
				 */
				th->last_signal = 0;
			else
				th->last_signal = sig;
		}
	}
}

/*
 * Map one waitpid() result for a known tid into struct zstop.
 * Updates per-thread state accordingly.  Returns:
 *   1  stop is user-visible: caller should fill st and return
 *   0  internal event consumed; caller should loop waitpid
 *  -1  hard error
 */
static int
zl_handle_event(struct zlinux_target *lt, pid_t tid, int status,
    struct zstop *st)
{
	struct zlinux_thread *th;
	int sig;
	int event;

	if (WIFEXITED(status) || WIFSIGNALED(status)) {
		int code = WIFEXITED(status) ?
		    WEXITSTATUS(status) : WTERMSIG(status);
		zl_mark_exited(lt, tid, code);
		if (zl_live_count(lt) == 0) {
			lt->exited = 1;
			lt->exit_code = code;
			st->reason = ZSTOP_EXIT;
			st->code = code;
			st->tid = (uint64_t)tid;
			st->addr = 0;
			return 1;
		}
		/* non-last thread exited; keep waiting silently */
		return 0;
	}
	if (!WIFSTOPPED(status))
		return 0;

	th = zl_find_any(lt, tid);
	if (th == NULL) {
		/* Unknown tid: may be a freshly-cloned child whose
		 * initial SIGSTOP arrived before we processed the
		 * parent's PTRACE_EVENT_CLONE.  Record it. */
		th = zl_add(lt, tid);
		if (th == NULL) {
			/* table full: detach it rather than leak */
			(void)ptrace(PTRACE_DETACH, tid, (void *)0,
			    (void *)0);
			return 0;
		}
	}
	th->stopped = 1;

	sig = WSTOPSIG(status);
	event = (status >> 16) & 0xffff;

	if (sig == SIGTRAP && event == PTRACE_EVENT_CLONE) {
		unsigned long newtid = 0;
		zl_set_options(th);
		if (ptrace(PTRACE_GETEVENTMSG, tid, (void *)0,
		    &newtid) == 0 && newtid != 0) {
			struct zlinux_thread *nt;
			nt = zl_add(lt, (pid_t)newtid);
			if (nt != NULL) {
				/*
				 * New child may already be stopped (its
				 * SIGSTOP arrives or has arrived).  Mark
				 * running for now; wait path will pick
				 * up the SIGSTOP and flip to stopped.
				 */
				nt->stopped = 0;
			}
		}
		th->last_signal = 0;
		/* resume the parent silently */
		(void)ptrace(PTRACE_CONT, tid, (void *)0, (void *)0);
		th->stopped = 0;
		return 0;
	}

	/*
	 * Initial SIGSTOP of a newly-cloned child.  Linux sends it
	 * with WSTOPSIG == SIGSTOP and PTRACE_O_* not yet applied.
	 * Set options and silently resume it.
	 */
	if (sig == SIGSTOP && !th->options_set) {
		zl_set_options(th);
		th->last_signal = 0;
		(void)ptrace(PTRACE_CONT, tid, (void *)0, (void *)0);
		th->stopped = 0;
		return 0;
	}
	zl_set_options(th);

	/* user-visible stop */
	st->tid = (uint64_t)tid;
	if (sig == SIGTRAP) {
		if (lt->singlestep_tid != 0 &&
		    (pid_t)lt->singlestep_tid == tid) {
			st->reason = ZSTOP_SINGLESTEP;
		} else {
			st->reason = ZSTOP_BREAKPOINT;
		}
		th->last_signal = 0;
	} else {
		st->reason = ZSTOP_SIGNAL;
		st->code = sig;
		th->last_signal = sig;
	}
	lt->singlestep_tid = 0;
	return 1;
}

int
ztarget_linux_wait(struct ztarget *t, struct zstop *st)
{
	struct zlinux_target *lt = zl_get(t);
	int status;
	pid_t r;
	int rc;

	if (lt == NULL || st == NULL)
		return -1;

	memset(st, 0, sizeof(*st));

	for (;;) {
		do {
			r = waitpid(-1, &status, __WALL);
		} while (r < 0 && errno == EINTR);
		if (r < 0) {
			st->reason = ZSTOP_ERROR;
			return -1;
		}
		rc = zl_handle_event(lt, r, status, st);
		if (rc < 0) {
			st->reason = ZSTOP_ERROR;
			return -1;
		}
		if (rc == 1)
			break;
		/* internal event consumed; keep waiting */
	}

	if (lt->exited) {
		t->state = ZTARGET_EXITED;
		t->tid = st->tid;
		return 0;
	}

	/* Best-effort all-stop: pause every other running thread. */
	zl_stop_all_except(lt, (pid_t)st->tid);

	/* Select the stopping thread. */
	lt->current_tid = (pid_t)st->tid;
	t->tid = st->tid;
	t->state = ZTARGET_STOPPED;

	/* Fill RIP for the stopping thread. */
#if defined(__x86_64__)
	{
		struct user_regs_struct u;
		if (ptrace(PTRACE_GETREGS, (pid_t)st->tid, (void *)0,
		    &u) == 0)
			st->addr = (uint64_t)u.rip;
	}
#endif
	return 0;
}

int
ztarget_linux_continue(struct ztarget *t)
{
	struct zlinux_target *lt = zl_get(t);
	int i;
	int resumed = 0;

	if (lt == NULL || lt->exited)
		return -1;

	for (i = 0; i < lt->nthreads; i++) {
		struct zlinux_thread *th = &lt->threads[i];
		int sig;
		if (th->tid == 0 || th->exited || !th->stopped)
			continue;
		sig = th->last_signal;
		if (ptrace(PTRACE_CONT, th->tid, (void *)0,
		    (void *)(long)sig) < 0) {
			if (errno == ESRCH) {
				th->exited = 1;
				continue;
			}
			continue;
		}
		th->stopped = 0;
		th->last_signal = 0;
		resumed++;
	}
	lt->singlestep_tid = 0;
	if (resumed == 0)
		return -1;
	t->state = ZTARGET_RUNNING;
	return 0;
}

int
ztarget_linux_singlestep(struct ztarget *t)
{
	struct zlinux_target *lt = zl_get(t);
	struct zlinux_thread *th;
	int sig;

	if (lt == NULL || lt->exited)
		return -1;
	th = zl_find(lt, lt->current_tid);
	if (th == NULL || !th->stopped)
		return -1;
	sig = th->last_signal;
	if (ptrace(PTRACE_SINGLESTEP, th->tid, (void *)0,
	    (void *)(long)sig) < 0)
		return -1;
	th->stopped = 0;
	th->last_signal = 0;
	lt->singlestep_tid = th->tid;
	t->state = ZTARGET_RUNNING;
	return 0;
}

/* ---------------- memory read/write ---------------- */

/*
 * Process memory is shared across all threads of a TGID, so
 * any traced tid may be used for PTRACE_PEEKDATA/POKEDATA.  We
 * use the currently selected thread, falling back to the main
 * TGID if no thread is selected yet.
 */
static pid_t
zl_io_tid(struct zlinux_target *lt)
{
	if (lt->current_tid != 0)
		return lt->current_tid;
	return lt->tgid;
}

int
ztarget_linux_read(struct ztarget *t, zaddr_t addr, void *buf, size_t len)
{
	struct zlinux_target *lt = zl_get(t);
	unsigned char *out;
	pid_t tid;
	size_t ws;

	if (lt == NULL)
		return -1;
	if (len == 0)
		return 0;
	if (buf == NULL)
		return -1;

	out = (unsigned char *)buf;
	ws = sizeof(long);
	tid = zl_io_tid(lt);

	while (len > 0) {
		zaddr_t aligned = addr & ~(zaddr_t)(ws - 1);
		size_t off = (size_t)(addr - aligned);
		size_t n = ws - off;
		long word;
		unsigned char wb[sizeof(long)];
		size_t i;

		if (n > len)
			n = len;
		errno = 0;
		word = ptrace(PTRACE_PEEKDATA, tid,
		    (void *)(uintptr_t)aligned, (void *)0);
		if (word == -1 && errno != 0)
			return -1;
		memcpy(wb, &word, ws);
		for (i = 0; i < n; i++)
			out[i] = wb[off + i];
		out += n;
		addr += n;
		len -= n;
	}
	return 0;
}

int
ztarget_linux_write(struct ztarget *t, zaddr_t addr, const void *buf,
    size_t len)
{
	struct zlinux_target *lt = zl_get(t);
	const unsigned char *in;
	pid_t tid;
	size_t ws;

	if (lt == NULL)
		return -1;
	if (len == 0)
		return 0;
	if (buf == NULL)
		return -1;

	in = (const unsigned char *)buf;
	ws = sizeof(long);
	tid = zl_io_tid(lt);

	while (len > 0) {
		zaddr_t aligned = addr & ~(zaddr_t)(ws - 1);
		size_t off = (size_t)(addr - aligned);
		size_t n = ws - off;
		long word;
		unsigned char wb[sizeof(long)];
		size_t i;

		if (n > len)
			n = len;
		errno = 0;
		word = ptrace(PTRACE_PEEKDATA, tid,
		    (void *)(uintptr_t)aligned, (void *)0);
		if (word == -1 && errno != 0)
			return -1;
		memcpy(wb, &word, ws);
		for (i = 0; i < n; i++)
			wb[off + i] = in[i];
		memcpy(&word, wb, ws);
		if (ptrace(PTRACE_POKEDATA, tid,
		    (void *)(uintptr_t)aligned,
		    (void *)word) < 0)
			return -1;
		in += n;
		addr += n;
		len -= n;
	}
	return 0;
}

int
ztarget_linux_flush_icache(struct ztarget *t, zaddr_t addr, size_t len)
{
	(void)t; (void)addr; (void)len;
	return 0;
}

/* ---------------- register access ---------------- */

#if defined(__x86_64__)

static void
zl_user_to_zregs(const struct user_regs_struct *u, struct zregs *r)
{
	r->rax = u->rax;
	r->rbx = u->rbx;
	r->rcx = u->rcx;
	r->rdx = u->rdx;
	r->rsi = u->rsi;
	r->rdi = u->rdi;
	r->rbp = u->rbp;
	r->rsp = u->rsp;
	r->r8  = u->r8;
	r->r9  = u->r9;
	r->r10 = u->r10;
	r->r11 = u->r11;
	r->r12 = u->r12;
	r->r13 = u->r13;
	r->r14 = u->r14;
	r->r15 = u->r15;
	r->rip = u->rip;
	r->rflags = u->eflags;
}

static void
zl_zregs_to_user(const struct zregs *r, struct user_regs_struct *u)
{
	u->rax = r->rax;
	u->rbx = r->rbx;
	u->rcx = r->rcx;
	u->rdx = r->rdx;
	u->rsi = r->rsi;
	u->rdi = r->rdi;
	u->rbp = r->rbp;
	u->rsp = r->rsp;
	u->r8  = r->r8;
	u->r9  = r->r9;
	u->r10 = r->r10;
	u->r11 = r->r11;
	u->r12 = r->r12;
	u->r13 = r->r13;
	u->r14 = r->r14;
	u->r15 = r->r15;
	u->rip = r->rip;
	u->eflags = r->rflags;
}

int
ztarget_linux_getregs(struct ztarget *t, struct zregs *r)
{
	struct zlinux_target *lt = zl_get(t);
	struct user_regs_struct u;

	if (lt == NULL || r == NULL)
		return -1;
	if (ptrace(PTRACE_GETREGS, lt->current_tid, (void *)0, &u) < 0)
		return -1;
	zl_user_to_zregs(&u, r);
	return 0;
}

int
ztarget_linux_setregs(struct ztarget *t, const struct zregs *r)
{
	struct zlinux_target *lt = zl_get(t);
	struct user_regs_struct u;

	if (lt == NULL || r == NULL)
		return -1;
	if (ptrace(PTRACE_GETREGS, lt->current_tid, (void *)0, &u) < 0)
		return -1;
	zl_zregs_to_user(r, &u);
	if (ptrace(PTRACE_SETREGS, lt->current_tid, (void *)0, &u) < 0)
		return -1;
	return 0;
}

static int
zl_debugreg_offset(int regno, long *offp)
{
	if (regno < 0 || regno > 7 || offp == NULL)
		return -1;
	*offp = (long)offsetof(struct user, u_debugreg[regno]);
	return 0;
}

int
ztarget_linux_get_debugreg(struct ztarget *t, int regno, uint64_t *vp)
{
	struct zlinux_target *lt = zl_get(t);
	long off;
	long v;

	if (lt == NULL || vp == NULL)
		return -1;
	if (zl_debugreg_offset(regno, &off) < 0)
		return -1;
	errno = 0;
	v = ptrace(PTRACE_PEEKUSER, lt->current_tid, (void *)off,
	    (void *)0);
	if (v == -1 && errno != 0)
		return -1;
	*vp = (uint64_t)(unsigned long)v;
	return 0;
}

int
ztarget_linux_set_debugreg(struct ztarget *t, int regno, uint64_t v)
{
	struct zlinux_target *lt = zl_get(t);
	long off;

	if (lt == NULL)
		return -1;
	if (zl_debugreg_offset(regno, &off) < 0)
		return -1;
	if (ptrace(PTRACE_POKEUSER, lt->current_tid, (void *)off,
	    (void *)(unsigned long)v) < 0)
		return -1;
	return 0;
}

int
ztarget_linux_set_debugreg_all(struct ztarget *t, int regno, uint64_t v)
{
	struct zlinux_target *lt = zl_get(t);
	long off;
	int i;
	int ok = 0;

	if (lt == NULL)
		return -1;
	if (zl_debugreg_offset(regno, &off) < 0)
		return -1;
	for (i = 0; i < lt->nthreads; i++) {
		struct zlinux_thread *th = &lt->threads[i];
		if (th->tid == 0 || th->exited)
			continue;
		if (ptrace(PTRACE_POKEUSER, th->tid, (void *)off,
		    (void *)(unsigned long)v) == 0)
			ok++;
	}
	return ok > 0 ? 0 : -1;
}

#else /* !__x86_64__ */

int
ztarget_linux_getregs(struct ztarget *t, struct zregs *r)
{
	(void)t; (void)r;
	return -1;
}

int
ztarget_linux_setregs(struct ztarget *t, const struct zregs *r)
{
	(void)t; (void)r;
	return -1;
}

int
ztarget_linux_get_debugreg(struct ztarget *t, int regno, uint64_t *vp)
{
	(void)t; (void)regno; (void)vp;
	return -1;
}

int
ztarget_linux_set_debugreg(struct ztarget *t, int regno, uint64_t v)
{
	(void)t; (void)regno; (void)v;
	return -1;
}

int
ztarget_linux_set_debugreg_all(struct ztarget *t, int regno, uint64_t v)
{
	(void)t; (void)regno; (void)v;
	return -1;
}

#endif /* __x86_64__ */

/* ---------------- thread API ---------------- */

int
ztarget_linux_thread_count(struct ztarget *t)
{
	struct zlinux_target *lt = zl_get(t);
	int i;
	int n = 0;

	if (lt == NULL)
		return 0;
	for (i = 0; i < lt->nthreads; i++) {
		if (lt->threads[i].tid != 0)
			n++;
	}
	return n;
}

int
ztarget_linux_thread_get(struct ztarget *t, int idx, struct zthread *out)
{
	struct zlinux_target *lt = zl_get(t);
	int i;
	int seen = 0;

	if (lt == NULL || out == NULL || idx < 0)
		return -1;
	for (i = 0; i < lt->nthreads; i++) {
		struct zlinux_thread *th = &lt->threads[i];
		if (th->tid == 0)
			continue;
		if (seen == idx) {
			out->tid = (uint64_t)th->tid;
			if (th->exited)
				out->state = ZTHREAD_EXITED;
			else if (th->stopped)
				out->state = ZTHREAD_STOPPED;
			else
				out->state = ZTHREAD_RUNNING;
			out->last_signal = th->last_signal;
			return 0;
		}
		seen++;
	}
	return -1;
}

int
ztarget_linux_select_thread(struct ztarget *t, uint64_t tid)
{
	struct zlinux_target *lt = zl_get(t);
	struct zlinux_thread *th;

	if (lt == NULL)
		return -1;
	if (tid == 0 || tid > 0x7fffffffULL)
		return -1;
	th = zl_find(lt, (pid_t)tid);
	if (th == NULL)
		return -1;
	lt->current_tid = th->tid;
	t->tid = (uint64_t)th->tid;
	return 0;
}

uint64_t
ztarget_linux_current_thread(struct ztarget *t)
{
	struct zlinux_target *lt = zl_get(t);
	if (lt == NULL)
		return 0;
	return (uint64_t)lt->current_tid;
}

int
ztarget_linux_refresh_threads(struct ztarget *t)
{
	struct zlinux_target *lt = zl_get(t);
	if (lt == NULL)
		return -1;
	return zl_attach_new_tasks(lt);
}

int
ztarget_linux_get_pending_signal(struct ztarget *t, uint64_t tid, int *sigp)
{
	struct zlinux_target *lt = zl_get(t);
	struct zlinux_thread *th;
	pid_t p;

	if (lt == NULL || sigp == NULL)
		return -1;
	if (tid == 0)
		p = lt->current_tid;
	else if (tid > 0x7fffffffULL)
		return -1;
	else
		p = (pid_t)tid;
	th = zl_find(lt, p);
	if (th == NULL)
		return -1;
	*sigp = th->last_signal;
	return 0;
}

int
ztarget_linux_set_pending_signal(struct ztarget *t, uint64_t tid, int sig)
{
	struct zlinux_target *lt = zl_get(t);
	struct zlinux_thread *th;
	pid_t p;

	if (lt == NULL)
		return -1;
	if (sig < 0 || sig >= ZDBG_MAX_SIGNALS)
		return -1;
	if (tid == 0)
		p = lt->current_tid;
	else if (tid > 0x7fffffffULL)
		return -1;
	else
		p = (pid_t)tid;
	th = zl_find(lt, p);
	if (th == NULL)
		return -1;
	th->last_signal = sig;
	return 0;
}

#endif /* __linux__ */
