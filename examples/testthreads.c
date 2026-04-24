/*
 * testthreads.c - multi-threaded manual target for zdbg.
 *
 * Spawns one worker thread that spins on a global watch flag,
 * then the main thread flips the flag after a short delay to
 * let the worker exit cleanly.  The program is deliberately
 * boring but observable:
 *
 *   sym zdbg_thread_watch
 *   hw  zdbg_thread_watch 4 w
 *   g
 *
 * triggers a write watchpoint on the main thread.  `th` lists
 * the worker + main, `th <tid>` selects either one.
 *
 * Pthreads is the only external dependency; it is linked in by
 * CMake through Threads::Threads.
 */

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

volatile int zdbg_thread_watch;

static void *
worker(void *arg)
{
	(void)arg;
	while (!zdbg_thread_watch)
		usleep(1000);
	return NULL;
}

int
main(void)
{
	pthread_t th;

	if (pthread_create(&th, NULL, worker, NULL) != 0) {
		fprintf(stderr, "pthread_create failed\n");
		return 1;
	}
	/* give zdbg time to attach/observe the worker thread */
	sleep(2);
	zdbg_thread_watch = 1;
	pthread_join(th, NULL);
	return 0;
}
