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
