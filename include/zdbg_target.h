/*
 * zdbg_target.h - OS-independent target abstraction.
 *
 * The real backends (ptrace on Linux, the Win32 Debug API on
 * Windows) plug in behind this interface.  A null backend is
 * used when no OS backend is active, so every entry point is
 * always safe to call.
 */

#ifndef ZDBG_TARGET_H
#define ZDBG_TARGET_H

#include "zdbg.h"
#include "zdbg_arch.h"
#include "zdbg_regs.h"

enum ztarget_state {
	ZTARGET_EMPTY = 0,
	ZTARGET_LOADED,
	ZTARGET_RUNNING,
	ZTARGET_STOPPED,
	ZTARGET_EXITED,
	ZTARGET_DETACHED
};

enum zstop_reason {
	ZSTOP_NONE = 0,
	ZSTOP_INITIAL,
	ZSTOP_BREAKPOINT,
	ZSTOP_SINGLESTEP,
	ZSTOP_SIGNAL,
	ZSTOP_EXCEPTION,
	ZSTOP_EXIT,
	ZSTOP_ERROR
};

struct zstop {
	enum zstop_reason reason;
	uint64_t addr;
	int code;
};

struct ztarget {
	enum ztarget_state state;
	enum zarch arch;

	uint64_t pid;
	uint64_t tid;

	void *os;
};

void ztarget_init(struct ztarget *t);
void ztarget_fini(struct ztarget *t);

int ztarget_launch(struct ztarget *t, int argc, char **argv);
int ztarget_attach(struct ztarget *t, uint64_t pid);
int ztarget_detach(struct ztarget *t);
int ztarget_kill(struct ztarget *t);

int ztarget_wait(struct ztarget *t, struct zstop *st);
int ztarget_continue(struct ztarget *t);
int ztarget_singlestep(struct ztarget *t);

int ztarget_read(struct ztarget *t, zaddr_t addr, void *buf, size_t len);
int ztarget_write(struct ztarget *t, zaddr_t addr, const void *buf, size_t len);
int ztarget_flush_icache(struct ztarget *t, zaddr_t addr, size_t len);

int ztarget_getregs(struct ztarget *t, struct zregs *r);
int ztarget_setregs(struct ztarget *t, const struct zregs *r);

/*
 * Backend entry points.  Implementations live in target_null.c,
 * os_linux/target_linux.c and os_windows/target_windows.c.  Only
 * one backend is active per build; src/target.c selects it.
 */

int ztarget_null_launch(struct ztarget *t, int argc, char **argv);
int ztarget_null_attach(struct ztarget *t, uint64_t pid);
int ztarget_null_detach(struct ztarget *t);
int ztarget_null_kill(struct ztarget *t);
int ztarget_null_wait(struct ztarget *t, struct zstop *st);
int ztarget_null_continue(struct ztarget *t);
int ztarget_null_singlestep(struct ztarget *t);
int ztarget_null_read(struct ztarget *t, zaddr_t addr, void *buf, size_t len);
int ztarget_null_write(struct ztarget *t, zaddr_t addr, const void *buf,
    size_t len);
int ztarget_null_flush_icache(struct ztarget *t, zaddr_t addr, size_t len);
int ztarget_null_getregs(struct ztarget *t, struct zregs *r);
int ztarget_null_setregs(struct ztarget *t, const struct zregs *r);

#if defined(__linux__)
int ztarget_linux_launch(struct ztarget *t, int argc, char **argv);
int ztarget_linux_attach(struct ztarget *t, uint64_t pid);
int ztarget_linux_detach(struct ztarget *t);
int ztarget_linux_kill(struct ztarget *t);
int ztarget_linux_wait(struct ztarget *t, struct zstop *st);
int ztarget_linux_continue(struct ztarget *t);
int ztarget_linux_singlestep(struct ztarget *t);
int ztarget_linux_read(struct ztarget *t, zaddr_t addr, void *buf, size_t len);
int ztarget_linux_write(struct ztarget *t, zaddr_t addr, const void *buf,
    size_t len);
int ztarget_linux_flush_icache(struct ztarget *t, zaddr_t addr, size_t len);
int ztarget_linux_getregs(struct ztarget *t, struct zregs *r);
int ztarget_linux_setregs(struct ztarget *t, const struct zregs *r);
#endif /* __linux__ */

#endif /* ZDBG_TARGET_H */
