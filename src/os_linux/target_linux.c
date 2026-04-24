/*
 * target_linux.c - Linux ptrace backend (framework stubs).
 *
 * These stubs compile only on Linux.  They must be replaced by
 * real ptrace logic in a later issue:
 *     fork + PTRACE_TRACEME + execvp
 *     waitpid
 *     PTRACE_PEEKDATA / POKEDATA
 *     PTRACE_GETREGS / SETREGS
 *     PTRACE_CONT
 *     PTRACE_SINGLESTEP
 *
 * Do not fake success: every function reports failure.
 */

#if defined(__linux__)

#include "zdbg_target.h"

int
ztarget_linux_launch(struct ztarget *t, int argc, char **argv)
{
	(void)t; (void)argc; (void)argv;
	return -1;
}

int
ztarget_linux_attach(struct ztarget *t, uint64_t pid)
{
	(void)t; (void)pid;
	return -1;
}

int
ztarget_linux_detach(struct ztarget *t)
{
	(void)t;
	return -1;
}

#endif /* __linux__ */
