/*
 * testsignals.c - small target used for manual signal-policy
 * testing under zdbg.  No pthreads, no faults in the default
 * path: SIGUSR1 and SIGUSR2 are enough to exercise pass/
 * suppress policy.
 *
 * The zdbg_signal_stage variable is volatile so it can be
 * inspected in a debugger session between raises.
 */

#include <signal.h>
#include <stdio.h>
#include <unistd.h>

volatile int zdbg_signal_stage;

static void
usr1_handler(int sig)
{
	(void)sig;
	zdbg_signal_stage++;
}

int
main(void)
{
	signal(SIGUSR1, usr1_handler);
	raise(SIGUSR1);
	zdbg_signal_stage++;
	raise(SIGUSR2);
	zdbg_signal_stage++;
	return 0;
}
