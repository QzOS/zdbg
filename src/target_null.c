/*
 * target_null.c - backend of last resort.
 *
 * Every entry point returns a clean error.  This lets higher
 * level code (REPL commands, breakpoint table) call target
 * functions unconditionally without crashing when no real
 * backend is attached.
 */

#include "zdbg_target.h"

int
ztarget_null_launch(struct ztarget *t, int argc, char **argv)
{
	(void)t; (void)argc; (void)argv;
	return -1;
}

int
ztarget_null_attach(struct ztarget *t, uint64_t pid)
{
	(void)t; (void)pid;
	return -1;
}

int
ztarget_null_detach(struct ztarget *t)
{
	(void)t;
	return -1;
}

int
ztarget_null_kill(struct ztarget *t)
{
	(void)t;
	return -1;
}

int
ztarget_null_wait(struct ztarget *t, struct zstop *st)
{
	(void)t;
	if (st != NULL) {
		st->reason = ZSTOP_ERROR;
		st->addr = 0;
		st->code = 0;
		st->tid = 0;
	}
	return -1;
}

int
ztarget_null_continue(struct ztarget *t)
{
	(void)t;
	return -1;
}

int
ztarget_null_singlestep(struct ztarget *t)
{
	(void)t;
	return -1;
}

int
ztarget_null_read(struct ztarget *t, zaddr_t addr, void *buf, size_t len)
{
	(void)t; (void)addr; (void)buf; (void)len;
	return -1;
}

int
ztarget_null_write(struct ztarget *t, zaddr_t addr, const void *buf, size_t len)
{
	(void)t; (void)addr; (void)buf; (void)len;
	return -1;
}

int
ztarget_null_flush_icache(struct ztarget *t, zaddr_t addr, size_t len)
{
	(void)t; (void)addr; (void)len;
	return 0;
}

int
ztarget_null_getregs(struct ztarget *t, struct zregs *r)
{
	(void)t; (void)r;
	return -1;
}

int
ztarget_null_setregs(struct ztarget *t, const struct zregs *r)
{
	(void)t; (void)r;
	return -1;
}

int
ztarget_null_get_debugreg(struct ztarget *t, int regno, uint64_t *vp)
{
	(void)t; (void)regno; (void)vp;
	return -1;
}

int
ztarget_null_set_debugreg(struct ztarget *t, int regno, uint64_t v)
{
	(void)t; (void)regno; (void)v;
	return -1;
}

int
ztarget_null_set_debugreg_all(struct ztarget *t, int regno, uint64_t v)
{
	(void)t; (void)regno; (void)v;
	return -1;
}

int
ztarget_null_thread_count(struct ztarget *t)
{
	(void)t;
	return 0;
}

int
ztarget_null_thread_get(struct ztarget *t, int idx, struct zthread *out)
{
	(void)t; (void)idx; (void)out;
	return -1;
}

int
ztarget_null_select_thread(struct ztarget *t, uint64_t tid)
{
	(void)t; (void)tid;
	return -1;
}

uint64_t
ztarget_null_current_thread(struct ztarget *t)
{
	if (t == NULL)
		return 0;
	return t->tid;
}

int
ztarget_null_refresh_threads(struct ztarget *t)
{
	(void)t;
	return 0;
}

int
ztarget_null_get_pending_signal(struct ztarget *t, uint64_t tid, int *sigp)
{
	(void)t; (void)tid; (void)sigp;
	return -1;
}

int
ztarget_null_set_pending_signal(struct ztarget *t, uint64_t tid, int sig)
{
	(void)t; (void)tid; (void)sig;
	return -1;
}
