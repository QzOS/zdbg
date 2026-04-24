/*
 * target_linux.c - Linux ptrace backend.
 *
 * This is the first real OS backend for zdbg.  It implements
 * launch, attach, detach, kill, wait, continue, single-step,
 * memory read/write, and register get/set against a single
 * traced x86-64 task.  Thread following, clone/fork events and
 * hardware breakpoints are intentionally out of scope here.
 *
 * All Linux-only headers and types are confined to this file so
 * that the public zdbg_target.h stays portable.
 *
 * Launch contract
 * ---------------
 * ztarget_linux_launch() performs the initial waitpid() for the
 * exec trap internally and returns with the target stopped
 * (state == ZTARGET_STOPPED).  The first SIGTRAP after exec is
 * normalized to ZSTOP_INITIAL.  The REPL may therefore read
 * registers and memory immediately after `l` without first
 * calling `wait`.
 */

#if defined(__linux__)

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__x86_64__)
#include <sys/user.h>
#endif

#include "zdbg_target.h"

struct zlinux_target {
	pid_t pid;
	pid_t tid;
	int attached;		/* attached via PTRACE_ATTACH */
	int launched;		/* created by us via fork+exec */
	int singlestep_pending;	/* next wait should report as singlestep */
	int exited;
	int exit_code;
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

/*
 * Consume any pending zombie for the traced task without blocking.
 * Used from kill/detach cleanup paths.
 */
static void
zl_reap_nohang(pid_t pid)
{
	int status;
	(void)waitpid(pid, &status, WNOHANG);
}

/* ---------------------------------------------------------------- */

int
ztarget_linux_launch(struct ztarget *t, int argc, char **argv)
{
	struct zlinux_target *lt;
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
		/* Child died before or during exec (e.g. exec failed). */
		zl_free(t);
		return -1;
	}
	if (!WIFSTOPPED(status)) {
		(void)kill(pid, SIGKILL);
		zl_reap_nohang(pid);
		zl_free(t);
		return -1;
	}

	lt->pid = pid;
	lt->tid = pid;
	lt->launched = 1;
	lt->attached = 0;
	lt->singlestep_pending = 0;
	lt->exited = 0;
	lt->exit_code = 0;

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
	pid_t p;
	int status;

	if (t == NULL || pid == 0 || pid > 0x7fffffffULL)
		return -1;
	if (t->state != ZTARGET_EMPTY)
		return -1;
	p = (pid_t)pid;

	lt = zl_alloc(t);
	if (lt == NULL)
		return -1;

	if (ptrace(PTRACE_ATTACH, p, (void *)0, (void *)0) < 0) {
		zl_free(t);
		return -1;
	}
	if (waitpid(p, &status, 0) < 0 || !WIFSTOPPED(status)) {
		(void)ptrace(PTRACE_DETACH, p, (void *)0, (void *)0);
		zl_free(t);
		return -1;
	}

	lt->pid = p;
	lt->tid = p;
	lt->attached = 1;
	lt->launched = 0;
	lt->singlestep_pending = 0;
	lt->exited = 0;
	lt->exit_code = 0;

	t->pid = (uint64_t)p;
	t->tid = (uint64_t)p;
	t->arch = ZARCH_X86_64;
	t->state = ZTARGET_STOPPED;
	return 0;
}

int
ztarget_linux_detach(struct ztarget *t)
{
	struct zlinux_target *lt = zl_get(t);

	if (lt == NULL)
		return -1;
	if (!lt->exited) {
		if (ptrace(PTRACE_DETACH, lt->pid, (void *)0, (void *)0) < 0) {
			/*
			 * Target may already be gone.  Best-effort:
			 * reap any pending zombie and carry on.
			 */
			zl_reap_nohang(lt->pid);
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

	if (lt == NULL)
		return -1;
	if (!lt->exited) {
		(void)kill(lt->pid, SIGKILL);
		/*
		 * A ptraced task is reaped by its tracer even if the
		 * task was created by a different process, so this is
		 * safe for both launched and attached targets.
		 */
		(void)waitpid(lt->pid, &status, 0);
	}
	t->state = ZTARGET_EXITED;
	zl_free(t);
	return 0;
}

/* ---------------------------------------------------------------- */

/*
 * Translate a raw waitpid() status into a struct zstop.  The
 * first post-launch/attach trap is consumed inside the launch
 * and attach paths themselves (see the launch contract at the
 * top of this file), so by the time we get here a SIGTRAP is
 * either the result of a PTRACE_SINGLESTEP we just issued or
 * something else (most commonly a software-breakpoint int3).
 * Later issues will need to distinguish software breakpoints
 * from syscall/exec/clone events and hardware watchpoint
 * causes; for now we deliberately keep the mapping approximate
 * and report non-singlestep SIGTRAPs as ZSTOP_BREAKPOINT.
 */
static void
zl_map_status(struct zlinux_target *lt, int status, struct zstop *st)
{
	if (st == NULL)
		return;
	st->reason = ZSTOP_NONE;
	st->addr = 0;
	st->code = 0;

	if (WIFEXITED(status)) {
		st->reason = ZSTOP_EXIT;
		st->code = WEXITSTATUS(status);
		lt->exited = 1;
		lt->exit_code = st->code;
		return;
	}
	if (WIFSIGNALED(status)) {
		st->reason = ZSTOP_EXIT;
		st->code = WTERMSIG(status);
		lt->exited = 1;
		lt->exit_code = st->code;
		return;
	}
	if (WIFSTOPPED(status)) {
		int sig = WSTOPSIG(status);
		if (sig == SIGTRAP) {
			if (lt->singlestep_pending)
				st->reason = ZSTOP_SINGLESTEP;
			else
				st->reason = ZSTOP_BREAKPOINT;
		} else {
			st->reason = ZSTOP_SIGNAL;
			st->code = sig;
		}
		lt->singlestep_pending = 0;
		return;
	}
	st->reason = ZSTOP_ERROR;
}

int
ztarget_linux_wait(struct ztarget *t, struct zstop *st)
{
	struct zlinux_target *lt = zl_get(t);
	int status;
	pid_t r;

	if (lt == NULL || st == NULL)
		return -1;

	do {
		r = waitpid(lt->pid, &status, 0);
	} while (r < 0 && errno == EINTR);
	if (r < 0) {
		st->reason = ZSTOP_ERROR;
		st->addr = 0;
		st->code = 0;
		return -1;
	}

	zl_map_status(lt, status, st);

	if (lt->exited) {
		t->state = ZTARGET_EXITED;
	} else {
		t->state = ZTARGET_STOPPED;
		/* Fill RIP for stops where registers are available. */
#if defined(__x86_64__)
		{
			struct user_regs_struct u;
			if (ptrace(PTRACE_GETREGS, lt->pid, (void *)0, &u) == 0)
				st->addr = (uint64_t)u.rip;
		}
#endif
	}
	return 0;
}

int
ztarget_linux_continue(struct ztarget *t)
{
	struct zlinux_target *lt = zl_get(t);

	if (lt == NULL || lt->exited)
		return -1;
	if (ptrace(PTRACE_CONT, lt->pid, (void *)0, (void *)0) < 0)
		return -1;
	lt->singlestep_pending = 0;
	t->state = ZTARGET_RUNNING;
	return 0;
}

int
ztarget_linux_singlestep(struct ztarget *t)
{
	struct zlinux_target *lt = zl_get(t);

	if (lt == NULL || lt->exited)
		return -1;
	if (ptrace(PTRACE_SINGLESTEP, lt->pid, (void *)0, (void *)0) < 0)
		return -1;
	lt->singlestep_pending = 1;
	t->state = ZTARGET_RUNNING;
	return 0;
}

/* ---------------------------------------------------------------- */

int
ztarget_linux_read(struct ztarget *t, zaddr_t addr, void *buf, size_t len)
{
	struct zlinux_target *lt = zl_get(t);
	unsigned char *out;
	size_t ws;

	if (lt == NULL)
		return -1;
	if (len == 0)
		return 0;
	if (buf == NULL)
		return -1;

	out = (unsigned char *)buf;
	ws = sizeof(long);

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
		word = ptrace(PTRACE_PEEKDATA, lt->pid, (void *)(uintptr_t)aligned,
		    (void *)0);
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
	size_t ws;

	if (lt == NULL)
		return -1;
	if (len == 0)
		return 0;
	if (buf == NULL)
		return -1;

	in = (const unsigned char *)buf;
	ws = sizeof(long);

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
		word = ptrace(PTRACE_PEEKDATA, lt->pid, (void *)(uintptr_t)aligned,
		    (void *)0);
		if (word == -1 && errno != 0)
			return -1;
		memcpy(wb, &word, ws);
		for (i = 0; i < n; i++)
			wb[off + i] = in[i];
		memcpy(&word, wb, ws);
		if (ptrace(PTRACE_POKEDATA, lt->pid, (void *)(uintptr_t)aligned,
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
	/*
	 * x86-64 keeps instruction and data caches coherent from the
	 * programmer's point of view; no explicit flush is needed
	 * after PTRACE_POKEDATA.  The command layer still calls us
	 * through the abstraction so ports to architectures that do
	 * need a flush can hook in here.
	 */
	(void)t; (void)addr; (void)len;
	return 0;
}

/* ---------------------------------------------------------------- */

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
	if (ptrace(PTRACE_GETREGS, lt->pid, (void *)0, &u) < 0)
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
	if (ptrace(PTRACE_GETREGS, lt->pid, (void *)0, &u) < 0)
		return -1;
	zl_zregs_to_user(r, &u);
	if (ptrace(PTRACE_SETREGS, lt->pid, (void *)0, &u) < 0)
		return -1;
	return 0;
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

#endif /* __x86_64__ */

#endif /* __linux__ */
