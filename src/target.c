/*
 * target.c - OS-independent target dispatcher.
 *
 * Chooses a backend at compile time.  On Linux the real ptrace
 * backend in src/os_linux/target_linux.c is used; on every other
 * platform the null backend keeps the rest of the program safe.
 */

#include <string.h>

#include "zdbg_target.h"

#if defined(__linux__)
#define ZBACKEND(fn) ztarget_linux_##fn
#elif defined(_WIN32)
#define ZBACKEND(fn) ztarget_windows_##fn
#else
#define ZBACKEND(fn) ztarget_null_##fn
#endif

void
ztarget_init(struct ztarget *t)
{
	if (t == NULL)
		return;
	memset(t, 0, sizeof(*t));
	t->state = ZTARGET_EMPTY;
	t->arch = ZARCH_X86_64;
}

void
ztarget_fini(struct ztarget *t)
{
	if (t == NULL)
		return;
	/*
	 * Best-effort cleanup through the backend.  A running or
	 * stopped target is detached so we do not leave orphaned
	 * traced processes behind.
	 */
	if (t->state == ZTARGET_RUNNING || t->state == ZTARGET_STOPPED)
		(void)ztarget_detach(t);
	memset(t, 0, sizeof(*t));
}

int
ztarget_launch(struct ztarget *t, int argc, char **argv)
{
	return ZBACKEND(launch)(t, argc, argv);
}

int
ztarget_attach(struct ztarget *t, uint64_t pid)
{
	return ZBACKEND(attach)(t, pid);
}

int
ztarget_detach(struct ztarget *t)
{
	return ZBACKEND(detach)(t);
}

int
ztarget_kill(struct ztarget *t)
{
	return ZBACKEND(kill)(t);
}

int
ztarget_wait(struct ztarget *t, struct zstop *st)
{
	return ZBACKEND(wait)(t, st);
}

int
ztarget_continue(struct ztarget *t)
{
	return ZBACKEND(continue)(t);
}

int
ztarget_singlestep(struct ztarget *t)
{
	return ZBACKEND(singlestep)(t);
}

int
ztarget_read(struct ztarget *t, zaddr_t addr, void *buf, size_t len)
{
	return ZBACKEND(read)(t, addr, buf, len);
}

int
ztarget_write(struct ztarget *t, zaddr_t addr, const void *buf, size_t len)
{
	return ZBACKEND(write)(t, addr, buf, len);
}

int
ztarget_flush_icache(struct ztarget *t, zaddr_t addr, size_t len)
{
	return ZBACKEND(flush_icache)(t, addr, len);
}

int
ztarget_getregs(struct ztarget *t, struct zregs *r)
{
	return ZBACKEND(getregs)(t, r);
}

int
ztarget_setregs(struct ztarget *t, const struct zregs *r)
{
	return ZBACKEND(setregs)(t, r);
}

int
ztarget_get_debugreg(struct ztarget *t, int regno, uint64_t *vp)
{
	return ZBACKEND(get_debugreg)(t, regno, vp);
}

int
ztarget_set_debugreg(struct ztarget *t, int regno, uint64_t v)
{
	return ZBACKEND(set_debugreg)(t, regno, v);
}

int
ztarget_set_debugreg_all(struct ztarget *t, int regno, uint64_t v)
{
	return ZBACKEND(set_debugreg_all)(t, regno, v);
}

int
ztarget_thread_count(struct ztarget *t)
{
	return ZBACKEND(thread_count)(t);
}

int
ztarget_thread_get(struct ztarget *t, int idx, struct zthread *out)
{
	return ZBACKEND(thread_get)(t, idx, out);
}

int
ztarget_select_thread(struct ztarget *t, uint64_t tid)
{
	return ZBACKEND(select_thread)(t, tid);
}

uint64_t
ztarget_current_thread(struct ztarget *t)
{
	return ZBACKEND(current_thread)(t);
}

int
ztarget_refresh_threads(struct ztarget *t)
{
	return ZBACKEND(refresh_threads)(t);
}

int
ztarget_get_pending_signal(struct ztarget *t, uint64_t tid, int *sigp)
{
	return ZBACKEND(get_pending_signal)(t, tid, sigp);
}

int
ztarget_set_pending_signal(struct ztarget *t, uint64_t tid, int sig)
{
	return ZBACKEND(set_pending_signal)(t, tid, sig);
}

int
ztarget_get_pending_exception(struct ztarget *t, uint64_t tid,
    uint32_t *codep, int *first_chancep, int *passp)
{
	return ZBACKEND(get_pending_exception)(t, tid, codep,
	    first_chancep, passp);
}

int
ztarget_set_pending_exception(struct ztarget *t, uint64_t tid,
    uint32_t code, int first_chance, int pass)
{
	return ZBACKEND(set_pending_exception)(t, tid, code, first_chance,
	    pass);
}

int
ztarget_clear_pending_exception(struct ztarget *t, uint64_t tid)
{
	return ZBACKEND(clear_pending_exception)(t, tid);
}
