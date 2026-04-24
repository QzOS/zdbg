/*
 * target_windows.c - Win32 Debug API backend (framework stubs).
 *
 * These stubs compile only on Windows.  They must be replaced
 * by real logic in a later issue:
 *     CreateProcess with DEBUG_ONLY_THIS_PROCESS
 *     DebugActiveProcess
 *     WaitForDebugEvent
 *     ContinueDebugEvent
 *     ReadProcessMemory / WriteProcessMemory
 *     GetThreadContext / SetThreadContext
 *     FlushInstructionCache
 *
 * <windows.h> must not be included anywhere else in the tree.
 */

#ifdef _WIN32

#include <windows.h>

#include "zdbg_target.h"

int
ztarget_win_launch(struct ztarget *t, int argc, char **argv)
{
	(void)t; (void)argc; (void)argv;
	return -1;
}

int
ztarget_win_attach(struct ztarget *t, uint64_t pid)
{
	(void)t; (void)pid;
	return -1;
}

int
ztarget_win_detach(struct ztarget *t)
{
	(void)t;
	return -1;
}

#endif /* _WIN32 */
