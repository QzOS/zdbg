/*
 * testio.c - tiny portable stdio echo target.
 *
 * Reads up to one line from stdin (no newline included), then
 * prints "out:<line>" to stdout and "err:<line>" to stderr and
 * exits with status 0.  EOF on stdin is handled as an empty
 * line.  Used by manual and scripted I/O redirection tests on
 * Linux and Windows.
 */

#include <stdio.h>
#include <string.h>

int
main(void)
{
	char buf[256];
	size_t n;

	if (fgets(buf, sizeof(buf), stdin) == NULL)
		buf[0] = 0;
	n = strlen(buf);
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		buf[--n] = 0;

	printf("out:%s\n", buf);
	fflush(stdout);
	fprintf(stderr, "err:%s\n", buf);
	fflush(stderr);
	return 0;
}
