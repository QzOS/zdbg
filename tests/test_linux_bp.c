/*
 * test_linux_bp.c - Linux integration test for software
 * breakpoint hit handling.
 *
 * Launches /bin/sleep under ptrace, pauses at the initial trap,
 * installs a breakpoint at the current RIP, continues, and then
 * verifies that:
 *   - zbp_handle_trap recognizes the hit and corrects RIP back
 *     to the breakpoint address
 *   - the breakpoint ends up uninstalled after the hit
 *   - after a single-step and zbp_install, the breakpoint is
 *     reinstalled and the original byte is replaced by 0xcc
 *
 * Skipped (exit 0) if ptrace or exec of /bin/sleep is denied.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "zdbg_arch.h"
#include "zdbg_bp.h"
#include "zdbg_target.h"
#include "zdbg_regs.h"

static int
ptrace_allowed(void)
{
	pid_t child;
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
	}
	return 1;
}

#define SKIP(msg) do { printf("SKIP: %s\n", msg); \
	ztarget_kill(&tgt); return 0; } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); \
	ztarget_kill(&tgt); return 1; } while (0)

int
main(void)
{
	struct ztarget tgt;
	struct zbp_table bt;
	struct zregs regs;
	struct zstop st;
	char *argv[3];
	zaddr_t bp_addr;
	uint8_t probe;
	int id;
	int hit_id;
	int rc;

	if (!ptrace_allowed()) {
		printf("SKIP: ptrace not permitted\n");
		return 0;
	}

	ztarget_init(&tgt);
	zbp_table_init(&bt, zarch_x86_64());

	argv[0] = (char *)"/bin/sleep";
	argv[1] = (char *)"30";
	argv[2] = NULL;
	if (ztarget_launch(&tgt, 2, argv, NULL) < 0) {
		printf("SKIP: launch failed (errno=%d)\n", errno);
		ztarget_fini(&tgt);
		return 0;
	}

	memset(&regs, 0, sizeof(regs));
	if (ztarget_getregs(&tgt, &regs) < 0)
		FAIL("getregs after launch");
	if (regs.rip == 0)
		FAIL("rip == 0");
	bp_addr = regs.rip;

	/* read original byte at bp_addr to compare later */
	if (ztarget_read(&tgt, bp_addr, &probe, 1) < 0)
		SKIP("cannot read target memory at initial rip");

	id = zbp_alloc(&bt, bp_addr, 0);
	if (id < 0)
		FAIL("alloc");
	if (zbp_enable(&tgt, &bt, id) < 0)
		FAIL("enable");
	if (!bt.bp[id].installed)
		FAIL("breakpoint not installed after enable");

	/* verify 0xcc was actually written */
	{
		uint8_t cc;
		if (ztarget_read(&tgt, bp_addr, &cc, 1) < 0)
			FAIL("read after install");
		if (cc != 0xcc)
			FAIL("byte at bp addr is not 0xcc after install");
	}

	/* continue: should trap immediately on the int3 */
	if (ztarget_continue(&tgt) < 0)
		FAIL("continue");
	memset(&st, 0, sizeof(st));
	if (ztarget_wait(&tgt, &st) < 0)
		FAIL("wait");
	if (st.reason != ZSTOP_BREAKPOINT)
		FAIL("expected breakpoint stop");

	if (ztarget_getregs(&tgt, &regs) < 0)
		FAIL("getregs after trap");
	if (regs.rip != bp_addr + 1)
		FAIL("rip should be bp+1 right after int3");

	hit_id = -1;
	rc = zbp_handle_trap(&tgt, &bt, &regs, &hit_id);
	if (rc != 1)
		FAIL("zbp_handle_trap did not recognize our breakpoint");
	if (hit_id != id)
		FAIL("wrong breakpoint id from handle_trap");
	if (regs.rip != bp_addr)
		FAIL("rip not corrected to bp address");
	if (bt.bp[id].installed)
		FAIL("breakpoint still marked installed after handle_trap");

	/* verify original byte is back in memory */
	{
		uint8_t b;
		if (ztarget_read(&tgt, bp_addr, &b, 1) < 0)
			FAIL("read after handle_trap");
		if (b != probe)
			FAIL("original byte not restored");
	}

	/* verify target registers really reflect corrected RIP */
	{
		struct zregs r2;
		memset(&r2, 0, sizeof(r2));
		if (ztarget_getregs(&tgt, &r2) < 0)
			FAIL("getregs after correction");
		if (r2.rip != bp_addr)
			FAIL("target rip not set to bp addr");
	}

	/* step the original instruction, then reinstall */
	if (ztarget_singlestep(&tgt) < 0)
		FAIL("singlestep");
	memset(&st, 0, sizeof(st));
	if (ztarget_wait(&tgt, &st) < 0)
		FAIL("wait after singlestep");
	if (st.reason != ZSTOP_SINGLESTEP)
		FAIL("expected single-step stop");

	if (zbp_install(&tgt, &bt, id) < 0)
		FAIL("reinstall");
	if (!bt.bp[id].installed)
		FAIL("not installed after reinstall");
	{
		uint8_t cc;
		if (ztarget_read(&tgt, bp_addr, &cc, 1) < 0)
			FAIL("read after reinstall");
		if (cc != 0xcc)
			FAIL("0xcc not present after reinstall");
	}

	/* cleanup: remove the breakpoint and kill the target */
	if (zbp_clear(&tgt, &bt, id) < 0)
		FAIL("clear");
	ztarget_kill(&tgt);
	ztarget_fini(&tgt);
	printf("OK\n");
	return 0;
}

#endif /* __linux__ */
