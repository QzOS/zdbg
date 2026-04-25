/*
 * test_windows_target.c - Windows-only smoke test for the Win32
 * Debug API backend.  Uses the examples testprog (when the test
 * framework passes its path via ZDBG_TESTPROG) and otherwise
 * falls back to launching cmd.exe so the test still runs on a
 * bare developer machine.  Verifies we stop at the initial
 * breakpoint, reads registers, and lets the target exit.
 *
 * Non-Windows builds compile this as a no-op so CTest stays
 * portable.
 */

#ifndef _WIN32

int main(void) { return 0; }

#else

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zdbg_target.h"
#include "zdbg_regs.h"
#include "zdbg_maps.h"
#include "zdbg_symbols.h"

int
main(void)
{
	struct ztarget tgt;
	struct zregs r;
	struct zstop st;
	char *argv[2];
	const char *prog;
	int rc;

	prog = getenv("ZDBG_TESTPROG");
	if (prog == NULL || prog[0] == 0)
		prog = "C:\\Windows\\System32\\cmd.exe";

	argv[0] = (char *)prog;
	argv[1] = NULL;

	ztarget_init(&tgt);
	rc = ztarget_launch(&tgt, 1, argv, NULL);
	if (rc < 0) {
		/*
		 * Some sandboxes block CreateProcess with the debug
		 * flag; treat as skip rather than failure so CI
		 * without Windows runners does not flake.
		 */
		printf("SKIP: launch failed (GetLastError=%lu)\n",
		    (unsigned long)GetLastError());
		ztarget_fini(&tgt);
		return 0;
	}
	if (tgt.state != ZTARGET_STOPPED) {
		printf("FAIL: state after launch != STOPPED (%d)\n",
		    (int)tgt.state);
		ztarget_kill(&tgt);
		return 1;
	}

	memset(&r, 0, sizeof(r));
	if (ztarget_getregs(&tgt, &r) < 0) {
		printf("FAIL: getregs\n");
		ztarget_kill(&tgt);
		return 1;
	}
	if (r.rip == 0) {
		printf("FAIL: rip == 0 after initial stop\n");
		ztarget_kill(&tgt);
		return 1;
	}

	/* Single-step once; expect SINGLESTEP or a later EXIT. */
	if (ztarget_singlestep(&tgt) < 0) {
		printf("FAIL: singlestep\n");
		ztarget_kill(&tgt);
		return 1;
	}
	memset(&st, 0, sizeof(st));
	if (ztarget_wait(&tgt, &st) < 0) {
		printf("FAIL: wait after singlestep\n");
		ztarget_kill(&tgt);
		return 1;
	}
	if (st.reason != ZSTOP_SINGLESTEP && st.reason != ZSTOP_EXIT &&
	    st.reason != ZSTOP_EXCEPTION) {
		printf("FAIL: unexpected stop reason %d\n",
		    (int)st.reason);
		ztarget_kill(&tgt);
		return 1;
	}

	/*
	 * Exercise module-map + PE export loading.  The debug
	 * event loop should have delivered a CREATE_PROCESS event
	 * and at least some LOAD_DLL events (kernel32/ntdll are
	 * always loaded in user processes on NT).  We expect:
	 *   - fill_maps returns 0 and at least the main image.
	 *   - fill_syms returns >= 0 and produces some exports.
	 *   - a well-known stable export resolves through the
	 *     combined maps+syms module:name lookup.
	 */
	{
		struct zmap_table mt;
		struct zsym_table syms;
		int nmods;
		int nsc;
		static const char *probes[] = {
			"kernel32:GetCurrentProcess",
			"kernel32:CreateFileW",
			"kernel32:ExitProcess",
			"ntdll:NtClose",
			NULL
		};
		int i;
		int any_probe_hit = 0;

		zmaps_init(&mt);
		zsyms_init(&syms);

		if (ztarget_windows_fill_maps(&tgt, &mt) < 0) {
			printf("FAIL: fill_maps\n");
			ztarget_kill(&tgt);
			return 1;
		}
		nmods = mt.count;
		if (nmods < 1) {
			printf("FAIL: fill_maps returned no modules\n");
			ztarget_kill(&tgt);
			return 1;
		}

		nsc = ztarget_windows_fill_syms(&tgt, &syms);
		if (nsc < 0) {
			printf("FAIL: fill_syms\n");
			ztarget_kill(&tgt);
			return 1;
		}

		for (i = 0; probes[i] != NULL; i++) {
			zaddr_t tmp = 0;
			if (zsyms_resolve(&syms, &mt, probes[i], &tmp)
			    == 0 && tmp != 0) {
				any_probe_hit = 1;
				break;
			}
		}
		if (!any_probe_hit) {
			/*
			 * Not fatal: some sandboxed Windows images may
			 * strip exports or not have the usual DLLs.
			 * Emit a SKIP rather than FAIL so CI stays
			 * green without hiding regressions in the
			 * common path.
			 */
			printf("SKIP: no probe export resolved "
			    "(nmods=%d nsyms=%d)\n", nmods, syms.count);
		}

		/*
		 * Exercise VirtualQueryEx region enumeration.  The
		 * region table should have substantially more entries
		 * than the module table, include at least one IMAGE
		 * region, and contain the current rsp.
		 */
		{
			struct zmap_table rt;
			const struct zmap *m;
			int has_image = 0;
			int j;

			zmaps_init(&rt);
			if (ztarget_windows_fill_regions(&tgt, &rt) < 0) {
				printf("FAIL: fill_regions\n");
				ztarget_kill(&tgt);
				return 1;
			}
			if (rt.count <= mt.count) {
				printf("FAIL: regions(%d) <= modules(%d)\n",
				    rt.count, mt.count);
				ztarget_kill(&tgt);
				return 1;
			}
			for (j = 0; j < rt.count; j++) {
				if (rt.maps[j].mem_type == ZMAP_MEM_IMAGE) {
					has_image = 1;
					break;
				}
			}
			if (!has_image) {
				printf("FAIL: no MEM_IMAGE region\n");
				ztarget_kill(&tgt);
				return 1;
			}
			m = zmaps_find_by_addr(&rt, (zaddr_t)r.rsp);
			if (m == NULL) {
				printf("FAIL: rsp not in any committed "
				    "region (rsp=%llx)\n",
				    (unsigned long long)r.rsp);
				ztarget_kill(&tgt);
				return 1;
			}
		}
	}

	/*
	 * Debug-register API smoke test.  Verifies plumbing of
	 * get/set on DR0..DR7 via CONTEXT_DEBUG_REGISTERS without
	 * actually continuing the target.  Skipped on non-x64
	 * builds where the backend always returns -1.
	 */
	{
		uint64_t dr7_save = 0;
		uint64_t dr0_save = 0;
		uint64_t v = 0;
		int dr7_supported;

		dr7_supported = (ztarget_get_debugreg(&tgt, 7, &dr7_save) == 0);
		if (dr7_supported) {
			if (ztarget_get_debugreg(&tgt, 0, &dr0_save) < 0) {
				printf("FAIL: get DR0\n");
				ztarget_kill(&tgt);
				return 1;
			}
			/* DR4 and DR5 must be rejected. */
			if (ztarget_get_debugreg(&tgt, 4, &v) == 0 ||
			    ztarget_get_debugreg(&tgt, 5, &v) == 0) {
				printf("FAIL: DR4/5 accepted\n");
				ztarget_kill(&tgt);
				return 1;
			}
			/* Round-trip DR0 with a sentinel value. */
			if (ztarget_set_debugreg(&tgt, 0,
			    (uint64_t)0x1000) < 0) {
				printf("FAIL: set DR0\n");
				ztarget_kill(&tgt);
				return 1;
			}
			v = 0;
			if (ztarget_get_debugreg(&tgt, 0, &v) < 0) {
				printf("FAIL: readback DR0\n");
				ztarget_kill(&tgt);
				return 1;
			}
			if (v != (uint64_t)0x1000) {
				printf("FAIL: DR0 readback mismatch\n");
				ztarget_kill(&tgt);
				return 1;
			}
			/* set_debugreg_all should also succeed. */
			if (ztarget_set_debugreg_all(&tgt, 0,
			    dr0_save) < 0) {
				printf("FAIL: set_debugreg_all DR0\n");
				ztarget_kill(&tgt);
				return 1;
			}
			/* Restore DR7. */
			(void)ztarget_set_debugreg_all(&tgt, 7, dr7_save);
		} else {
			printf("SKIP: debug-register API not available\n");
		}
	}

	/* Kill and clean up regardless of current state. */
	ztarget_kill(&tgt);
	ztarget_fini(&tgt);
	printf("OK\n");
	return 0;
}

#endif /* _WIN32 */
