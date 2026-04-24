/*
 * target.c - OS-independent target dispatcher.
 *
 * Chooses a backend at compile time.  The initial framework
 * routes every call to the null backend on all platforms; the
 * Linux and Windows backend files exist so later issues can
 * implement them without having to re-plumb the dispatcher.
 */

#include <string.h>

#include "zdbg_target.h"

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
	 * Best-effort detach through the backend.  The null backend
	 * accepts this as a no-op.  Real backends will clean up
	 * their per-target state here in later issues.
	 */
	if (t->state == ZTARGET_RUNNING || t->state == ZTARGET_STOPPED)
		(void)ztarget_detach(t);
	memset(t, 0, sizeof(*t));
}

int
ztarget_launch(struct ztarget *t, int argc, char **argv)
{
	return ztarget_null_launch(t, argc, argv);
}

int
ztarget_attach(struct ztarget *t, uint64_t pid)
{
	return ztarget_null_attach(t, pid);
}

int
ztarget_detach(struct ztarget *t)
{
	return ztarget_null_detach(t);
}

int
ztarget_kill(struct ztarget *t)
{
	return ztarget_null_kill(t);
}

int
ztarget_wait(struct ztarget *t, struct zstop *st)
{
	return ztarget_null_wait(t, st);
}

int
ztarget_continue(struct ztarget *t)
{
	return ztarget_null_continue(t);
}

int
ztarget_singlestep(struct ztarget *t)
{
	return ztarget_null_singlestep(t);
}

int
ztarget_read(struct ztarget *t, zaddr_t addr, void *buf, size_t len)
{
	return ztarget_null_read(t, addr, buf, len);
}

int
ztarget_write(struct ztarget *t, zaddr_t addr, const void *buf, size_t len)
{
	return ztarget_null_write(t, addr, buf, len);
}

int
ztarget_flush_icache(struct ztarget *t, zaddr_t addr, size_t len)
{
	return ztarget_null_flush_icache(t, addr, len);
}

int
ztarget_getregs(struct ztarget *t, struct zregs *r)
{
	return ztarget_null_getregs(t, r);
}

int
ztarget_setregs(struct ztarget *t, const struct zregs *r)
{
	return ztarget_null_setregs(t, r);
}
