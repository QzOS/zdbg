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
#include "zdbg_stdio.h"

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
	/*
	 * TID of the thread that produced this stop.  Set by the
	 * backend.  Zero when no thread context applies (e.g. when
	 * the whole target has exited on the null backend).
	 */
	uint64_t tid;
	/*
	 * Windows first-chance flag for ZSTOP_EXCEPTION stops.
	 * Set from EXCEPTION_DEBUG_INFO.dwFirstChance by the
	 * Windows backend: 1 for first-chance, 0 for second-
	 * chance.  Unused (zero) on other backends and for non-
	 * exception stops.
	 */
	int first_chance;
};

/*
 * Maximum number of traced threads the target layer tracks in
 * a fixed-size table.  Real processes with more threads than
 * this are truncated; ptrace wait handling must still cope
 * with arbitrary traced tasks, but they will not show up in
 * the thread list.
 */
#define ZDBG_MAX_THREADS 128

enum zthread_state {
	ZTHREAD_EMPTY = 0,
	ZTHREAD_RUNNING,
	ZTHREAD_STOPPED,
	ZTHREAD_EXITED
};

/*
 * Small snapshot of one traced thread.  Returned by
 * ztarget_thread_get().  Backend-private state (pending
 * signals, ptrace option flags, etc.) is intentionally not
 * exposed here.
 */
struct zthread {
	uint64_t tid;
	enum zthread_state state;
	int last_signal;
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

int ztarget_launch(struct ztarget *t, int argc, char **argv,
    const struct zstdio_config *stdio_cfg);
int ztarget_attach(struct ztarget *t, uint64_t pid);
int ztarget_detach(struct ztarget *t);
int ztarget_kill(struct ztarget *t);

int ztarget_wait(struct ztarget *t, struct zstop *st);
/*
 * Continue all stopped non-exited traced threads (all-stop
 * policy).  See the issue #18 notes for caveats: software
 * breakpoint rearm is best-effort under multi-threaded loads.
 */
int ztarget_continue(struct ztarget *t);
/*
 * Single-step only the currently selected thread.  Other
 * stopped threads remain stopped when possible.
 */
int ztarget_singlestep(struct ztarget *t);

/*
 * Basic Linux thread awareness.  Fixed-size snapshot of the
 * traced threads is kept inside the backend; the command
 * layer asks for it through the accessors below.  On targets
 * that know about only one task these still return a single
 * (main) entry.
 */
int ztarget_thread_count(struct ztarget *t);
int ztarget_thread_get(struct ztarget *t, int idx, struct zthread *out);
int ztarget_select_thread(struct ztarget *t, uint64_t tid);
uint64_t ztarget_current_thread(struct ztarget *t);
int ztarget_refresh_threads(struct ztarget *t);

int ztarget_read(struct ztarget *t, zaddr_t addr, void *buf, size_t len);
int ztarget_write(struct ztarget *t, zaddr_t addr, const void *buf, size_t len);
int ztarget_flush_icache(struct ztarget *t, zaddr_t addr, size_t len);

int ztarget_getregs(struct ztarget *t, struct zregs *r);
int ztarget_setregs(struct ztarget *t, const struct zregs *r);

/*
 * Debug register access.  regno selects DR0..DR7; only DR0..DR3,
 * DR6 and DR7 are actually used by zdbg.  Returns 0 on success
 * and -1 on failure or when the backend/platform does not
 * support hardware debug registers.  The target must be stopped.
 */
int ztarget_get_debugreg(struct ztarget *t, int regno, uint64_t *vp);
int ztarget_set_debugreg(struct ztarget *t, int regno, uint64_t v);

/*
 * Write the given debug register to every currently known
 * traced thread.  This is the primitive used by the hardware
 * breakpoint/watchpoint layer to make DRn slots effective in
 * multi-threaded processes.  Best-effort: failures for
 * individual threads are swallowed, the function returns -1
 * only when no thread could be programmed at all.
 */
int ztarget_set_debugreg_all(struct ztarget *t, int regno, uint64_t v);

/*
 * Pending-signal access for the selected or specified thread.
 * tid == 0 means "current selected thread".  sig == 0 clears
 * the pending signal.  Returns 0 on success, -1 on failure or
 * when the backend does not track pending signals.
 *
 * "Pending" here refers to the signal the backend would
 * redeliver to the tracee on the next PTRACE_CONT/SINGLESTEP.
 * Reading does not consume the pending signal.
 */
int ztarget_get_pending_signal(struct ztarget *t, uint64_t tid, int *sigp);
int ztarget_set_pending_signal(struct ztarget *t, uint64_t tid, int sig);

/*
 * Pending Windows exception control for the selected or
 * specified thread.  tid == 0 means "current selected thread".
 * These are meaningful only on the Windows backend; every
 * other backend returns -1 cleanly (no Windows Debug API
 * pending exception exists).
 *
 * ztarget_get_pending_exception reports the Windows exception
 * currently pending from WaitForDebugEvent.  *codep receives
 * the Win32 ExceptionCode, *first_chancep receives
 * EXCEPTION_DEBUG_INFO.dwFirstChance as 1/0, and *passp
 * receives the current continuation state: 1 when the next
 * ContinueDebugEvent will use DBG_EXCEPTION_NOT_HANDLED and 0
 * for DBG_CONTINUE.  Returns 0 on success and -1 when no
 * exception is pending or the backend is not Windows.
 *
 * ztarget_set_pending_exception updates only the continuation
 * status for the pending exception: pass == 1 selects
 * DBG_EXCEPTION_NOT_HANDLED, pass == 0 selects DBG_CONTINUE.
 * The code/first_chance parameters must match the pending
 * event; they are compared rather than used to invent a new
 * exception (injection is not supported).
 *
 * ztarget_clear_pending_exception forces the pending event to
 * continue with DBG_CONTINUE, i.e. the exception is treated
 * as handled by the debugger and suppressed.
 */
int ztarget_get_pending_exception(struct ztarget *t, uint64_t tid,
    uint32_t *codep, int *first_chancep, int *passp);
int ztarget_set_pending_exception(struct ztarget *t, uint64_t tid,
    uint32_t code, int first_chance, int pass);
int ztarget_clear_pending_exception(struct ztarget *t, uint64_t tid);

/*
 * Backend entry points.  Implementations live in target_null.c,
 * os_linux/target_linux.c and os_windows/target_windows.c.  Only
 * one backend is active per build; src/target.c selects it.
 */

int ztarget_null_launch(struct ztarget *t, int argc, char **argv,
    const struct zstdio_config *stdio_cfg);
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
int ztarget_null_get_debugreg(struct ztarget *t, int regno, uint64_t *vp);
int ztarget_null_set_debugreg(struct ztarget *t, int regno, uint64_t v);
int ztarget_null_set_debugreg_all(struct ztarget *t, int regno, uint64_t v);
int ztarget_null_thread_count(struct ztarget *t);
int ztarget_null_thread_get(struct ztarget *t, int idx, struct zthread *out);
int ztarget_null_select_thread(struct ztarget *t, uint64_t tid);
uint64_t ztarget_null_current_thread(struct ztarget *t);
int ztarget_null_refresh_threads(struct ztarget *t);
int ztarget_null_get_pending_signal(struct ztarget *t, uint64_t tid,
    int *sigp);
int ztarget_null_set_pending_signal(struct ztarget *t, uint64_t tid,
    int sig);
int ztarget_null_get_pending_exception(struct ztarget *t, uint64_t tid,
    uint32_t *codep, int *first_chancep, int *passp);
int ztarget_null_set_pending_exception(struct ztarget *t, uint64_t tid,
    uint32_t code, int first_chance, int pass);
int ztarget_null_clear_pending_exception(struct ztarget *t, uint64_t tid);

#if defined(__linux__)
int ztarget_linux_launch(struct ztarget *t, int argc, char **argv,
    const struct zstdio_config *stdio_cfg);
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
int ztarget_linux_get_debugreg(struct ztarget *t, int regno, uint64_t *vp);
int ztarget_linux_set_debugreg(struct ztarget *t, int regno, uint64_t v);
int ztarget_linux_set_debugreg_all(struct ztarget *t, int regno, uint64_t v);
int ztarget_linux_thread_count(struct ztarget *t);
int ztarget_linux_thread_get(struct ztarget *t, int idx, struct zthread *out);
int ztarget_linux_select_thread(struct ztarget *t, uint64_t tid);
uint64_t ztarget_linux_current_thread(struct ztarget *t);
int ztarget_linux_refresh_threads(struct ztarget *t);
int ztarget_linux_get_pending_signal(struct ztarget *t, uint64_t tid,
    int *sigp);
int ztarget_linux_set_pending_signal(struct ztarget *t, uint64_t tid,
    int sig);
int ztarget_linux_get_pending_exception(struct ztarget *t, uint64_t tid,
    uint32_t *codep, int *first_chancep, int *passp);
int ztarget_linux_set_pending_exception(struct ztarget *t, uint64_t tid,
    uint32_t code, int first_chance, int pass);
int ztarget_linux_clear_pending_exception(struct ztarget *t, uint64_t tid);
#endif /* __linux__ */

#if defined(_WIN32)
/*
 * Forward-declared table types used by Windows-specific fill
 * helpers.  Declared here (rather than via includes) to keep
 * direction of header dependencies clean: target.h does not
 * need to know about map/symbol internals; pointers are enough.
 */
struct zmap_table;
struct zsym_table;

int ztarget_windows_launch(struct ztarget *t, int argc, char **argv,
    const struct zstdio_config *stdio_cfg);
int ztarget_windows_attach(struct ztarget *t, uint64_t pid);
int ztarget_windows_detach(struct ztarget *t);
int ztarget_windows_kill(struct ztarget *t);
int ztarget_windows_wait(struct ztarget *t, struct zstop *st);
int ztarget_windows_continue(struct ztarget *t);
int ztarget_windows_singlestep(struct ztarget *t);
int ztarget_windows_read(struct ztarget *t, zaddr_t addr, void *buf,
    size_t len);
int ztarget_windows_write(struct ztarget *t, zaddr_t addr, const void *buf,
    size_t len);
int ztarget_windows_flush_icache(struct ztarget *t, zaddr_t addr, size_t len);
int ztarget_windows_getregs(struct ztarget *t, struct zregs *r);
int ztarget_windows_setregs(struct ztarget *t, const struct zregs *r);
int ztarget_windows_get_debugreg(struct ztarget *t, int regno, uint64_t *vp);
int ztarget_windows_set_debugreg(struct ztarget *t, int regno, uint64_t v);
int ztarget_windows_set_debugreg_all(struct ztarget *t, int regno, uint64_t v);
int ztarget_windows_thread_count(struct ztarget *t);
int ztarget_windows_thread_get(struct ztarget *t, int idx,
    struct zthread *out);
int ztarget_windows_select_thread(struct ztarget *t, uint64_t tid);
uint64_t ztarget_windows_current_thread(struct ztarget *t);
int ztarget_windows_refresh_threads(struct ztarget *t);
int ztarget_windows_get_pending_signal(struct ztarget *t, uint64_t tid,
    int *sigp);
int ztarget_windows_set_pending_signal(struct ztarget *t, uint64_t tid,
    int sig);
int ztarget_windows_get_pending_exception(struct ztarget *t, uint64_t tid,
    uint32_t *codep, int *first_chancep, int *passp);
int ztarget_windows_set_pending_exception(struct ztarget *t, uint64_t tid,
    uint32_t code, int first_chance, int pass);
int ztarget_windows_clear_pending_exception(struct ztarget *t, uint64_t tid);

/*
 * Fill *mt with one synthetic map per currently-loaded module
 * recorded from Windows debug events.  Each map covers [base,
 * base+SizeOfImage), offset=0, perms="r-xp", name=image path
 * (best effort).  raw_file_offset_valid is always 0: PE images
 * are mapped with section alignment/gaps, so file byte offsets
 * are not simply addr - base.  Returns 0 on success and -1 if
 * the target has no backend state.
 */
int ztarget_windows_fill_maps(struct ztarget *t, struct zmap_table *mt);

/*
 * Enumerate committed memory regions in the target via
 * VirtualQueryEx.  Each region becomes a struct zmap with
 * kind=ZMAP_KIND_REGION, mem_type derived from MEMORY_BASIC_
 * INFORMATION.Type, perms derived from .Protect, and name
 * "[private]" / "[mapped]" / module-path-when-image.
 * raw_file_offset_valid is always 0.  Returns 0 on success,
 * -1 if the target has no backend state.
 */
int ztarget_windows_fill_regions(struct ztarget *t, struct zmap_table *mt);

/*
 * Populate *st with PE export symbols from currently-loaded
 * modules.  Parses IMAGE_EXPORT_DIRECTORY from target memory
 * using module_base + RVA, skipping ordinal-only exports and
 * forwarded exports (whose function RVA falls inside the
 * export directory range).  Returns the number of modules
 * scanned on success, -1 on argument error.
 */
int ztarget_windows_fill_syms(struct ztarget *t, struct zsym_table *st);
#endif /* _WIN32 */

#endif /* ZDBG_TARGET_H */
