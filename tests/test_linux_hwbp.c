/*
 * test_linux_hwbp.c - Linux integration test for hardware exec
 * breakpoints via DR0-DR7.
 *
 * Launches /bin/sleep under ptrace, installs a hardware execute
 * breakpoint at the initial RIP, continues, and verifies:
 *   - the trap is recognized via DR6 bit 0
 *   - RIP on stop equals the watched address (no RIP-1 fixup)
 *   - the byte at the watched address was NOT patched to 0xcc
 *   - DR6 is cleared afterwards
 *
 * Skipped (exit 0) if ptrace is denied or debug-register access
 * fails (e.g. inside a restricted sandbox).
 */

#if !defined(__linux__) || !defined(__x86_64__)
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

#include "zdbg_hwbp.h"
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

#define SKIP(msg) do { printf("SKIP: %s\n", msg); \
	ztarget_kill(&tgt); ztarget_fini(&tgt); return 0; } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); \
	ztarget_kill(&tgt); ztarget_fini(&tgt); return 1; } while (0)

int
main(void)
{
	struct ztarget tgt;
	struct zhwbp_table ht;
	struct zregs regs;
	struct zstop st;
	char *argv[3];
	zaddr_t bp_addr;
	uint8_t orig_byte;
	int id;
	uint64_t probe;

	if (!ptrace_allowed()) {
		printf("SKIP: ptrace not permitted\n");
		return 0;
	}

	ztarget_init(&tgt);
	zhwbp_table_init(&ht);

	argv[0] = (char *)"/bin/sleep";
	argv[1] = (char *)"30";
	argv[2] = NULL;
	if (ztarget_launch(&tgt, 2, argv) < 0) {
		printf("SKIP: launch failed (errno=%d)\n", errno);
		ztarget_fini(&tgt);
		return 0;
	}

	/* Quick debug-register availability probe: get DR7. */
	if (ztarget_get_debugreg(&tgt, 7, &probe) < 0)
		SKIP("debug register access not available");

	memset(&regs, 0, sizeof(regs));
	if (ztarget_getregs(&tgt, &regs) < 0)
		FAIL("getregs after launch");
	if (regs.rip == 0)
		FAIL("rip == 0");
	bp_addr = regs.rip;

	if (ztarget_read(&tgt, bp_addr, &orig_byte, 1) < 0)
		SKIP("cannot read initial rip");

	id = zhwbp_alloc(&ht, bp_addr, ZHWBP_EXEC, 1);
	if (id != 0)
		FAIL("alloc slot 0");
	if (zhwbp_enable(&tgt, &ht, id) < 0)
		FAIL("enable");

	/* Verify DR0 == bp_addr and DR7 L0 bit set. */
	{
		uint64_t dr0 = 0;
		uint64_t dr7 = 0;
		if (ztarget_get_debugreg(&tgt, 0, &dr0) < 0)
			FAIL("read DR0");
		if (dr0 != (uint64_t)bp_addr)
			FAIL("DR0 did not receive watched address");
		if (ztarget_get_debugreg(&tgt, 7, &dr7) < 0)
			FAIL("read DR7");
		if ((dr7 & 0x1) == 0)
			FAIL("L0 not set in DR7");
	}

	/* Verify byte at bp_addr is NOT patched to 0xcc. */
	{
		uint8_t b;
		if (ztarget_read(&tgt, bp_addr, &b, 1) < 0)
			FAIL("read after hwbp enable");
		if (b == 0xcc && orig_byte != 0xcc)
			FAIL("hwbp patched code byte with 0xcc");
		if (b != orig_byte)
			FAIL("original byte changed by hwbp");
	}

	/* Continue: should trap immediately on first instruction. */
	if (ztarget_continue(&tgt) < 0)
		FAIL("continue");
	memset(&st, 0, sizeof(st));
	if (ztarget_wait(&tgt, &st) < 0)
		FAIL("wait");
	if (st.reason != ZSTOP_BREAKPOINT)
		FAIL("expected breakpoint stop");

	if (ztarget_getregs(&tgt, &regs) < 0)
		FAIL("getregs after trap");
	/* Hardware exec: RIP should be at watched addr, not addr+1. */
	if (regs.rip != bp_addr)
		FAIL("rip not at watched address");

	{
		int hid = -1;
		uint64_t dr6 = 0;
		int rc = zhwbp_handle_trap(&tgt, &ht, &hid, &dr6);
		if (rc != 1)
			FAIL("hwbp handler did not claim trap");
		if (hid != id)
			FAIL("wrong slot id");
		if ((dr6 & 0x1) == 0)
			FAIL("DR6 B0 not set at trap");
		/* DR6 should be cleared afterwards. */
		{
			uint64_t dr6b = 0;
			if (ztarget_get_debugreg(&tgt, 6, &dr6b) < 0)
				FAIL("read DR6 after handle");
			if ((dr6b & 0xf) != 0)
				FAIL("DR6 B0..B3 not cleared");
		}
	}

	/* Clear + verify DR7 L0 cleared. */
	if (zhwbp_clear(&tgt, &ht, id) < 0)
		FAIL("clear");
	{
		uint64_t dr7 = 0;
		if (ztarget_get_debugreg(&tgt, 7, &dr7) < 0)
			FAIL("read DR7 after clear");
		if ((dr7 & 0x1) != 0)
			FAIL("L0 still set after clear");
	}

	ztarget_kill(&tgt);
	ztarget_fini(&tgt);
	printf("OK\n");
	return 0;
}

#endif /* __linux__ && __x86_64__ */
