/*
 * signal.c - signal name parsing/formatting and policy table.
 *
 * The name table below lists the signals zdbg recognizes by
 * name.  The numbers are the standard Linux user-space signal
 * numbers; they match Linux ABI on x86-64 and most other
 * architectures where zdbg currently cares.
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "zdbg_signal.h"

struct zsig_ent {
	int num;
	const char *name;
};

/*
 * Common Linux signal numbers.  Keep the list compact; the
 * exact set is what the issue asked for.
 */
static const struct zsig_ent zsig_names[] = {
	{  1, "SIGHUP"   },
	{  2, "SIGINT"   },
	{  3, "SIGQUIT"  },
	{  4, "SIGILL"   },
	{  5, "SIGTRAP"  },
	{  6, "SIGABRT"  },
	{  7, "SIGBUS"   },
	{  8, "SIGFPE"   },
	{  9, "SIGKILL"  },
	{ 10, "SIGUSR1"  },
	{ 11, "SIGSEGV"  },
	{ 12, "SIGUSR2"  },
	{ 13, "SIGPIPE"  },
	{ 14, "SIGALRM"  },
	{ 15, "SIGTERM"  },
	{ 17, "SIGCHLD"  },
	{ 18, "SIGCONT"  },
	{ 19, "SIGSTOP"  },
	{ 20, "SIGTSTP"  },
	{ 21, "SIGTTIN"  },
	{ 22, "SIGTTOU"  },
	{ 23, "SIGURG"   },
	{ 24, "SIGXCPU"  },
	{ 25, "SIGXFSZ"  },
	{ 26, "SIGVTALRM"},
	{ 27, "SIGPROF"  },
	{ 28, "SIGWINCH" },
	{ 31, "SIGSYS"   }
};

static const size_t zsig_names_n =
    sizeof(zsig_names) / sizeof(zsig_names[0]);

const char *
zsig_name(int sig)
{
	size_t i;

	for (i = 0; i < zsig_names_n; i++) {
		if (zsig_names[i].num == sig)
			return zsig_names[i].name;
	}
	return "SIG?";
}

static int
ieq(const char *a, const char *b)
{
	while (*a && *b) {
		int ca = tolower((unsigned char)*a);
		int cb = tolower((unsigned char)*b);
		if (ca != cb)
			return 0;
		a++;
		b++;
	}
	return *a == 0 && *b == 0;
}

static int
parse_dec(const char *s, int *vp)
{
	int v = 0;
	int any = 0;

	while (*s) {
		if (!isdigit((unsigned char)*s))
			return -1;
		v = v * 10 + (*s - '0');
		if (v < 0 || v >= ZDBG_MAX_SIGNALS)
			return -1;
		s++;
		any = 1;
	}
	if (!any)
		return -1;
	*vp = v;
	return 0;
}

static int
parse_hex(const char *s, int *vp)
{
	int v = 0;
	int any = 0;

	while (*s) {
		int d;
		unsigned char c = (unsigned char)*s;
		if (c >= '0' && c <= '9')
			d = c - '0';
		else if (c >= 'a' && c <= 'f')
			d = 10 + (c - 'a');
		else if (c >= 'A' && c <= 'F')
			d = 10 + (c - 'A');
		else
			return -1;
		v = v * 16 + d;
		if (v < 0 || v >= ZDBG_MAX_SIGNALS)
			return -1;
		s++;
		any = 1;
	}
	if (!any)
		return -1;
	*vp = v;
	return 0;
}

int
zsig_parse(const char *s, int *sigp)
{
	char buf[32];
	size_t n;
	size_t i;

	if (s == NULL || sigp == NULL)
		return -1;
	/* strip leading whitespace */
	while (*s == ' ' || *s == '\t')
		s++;
	n = strlen(s);
	while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' ||
	    s[n - 1] == '\n' || s[n - 1] == '\r'))
		n--;
	if (n == 0 || n >= sizeof(buf))
		return -1;
	for (i = 0; i < n; i++)
		buf[i] = s[i];
	buf[n] = 0;

	/* "#NN" -> decimal */
	if (buf[0] == '#')
		return parse_dec(buf + 1, sigp);

	/* "0xNN" -> hex */
	if (buf[0] == '0' && (buf[1] == 'x' || buf[1] == 'X'))
		return parse_hex(buf + 2, sigp);

	/* plain digits -> decimal */
	if (isdigit((unsigned char)buf[0]))
		return parse_dec(buf, sigp);

	/* name lookup, both "SIGSEGV" and "SEGV" */
	for (i = 0; i < zsig_names_n; i++) {
		const char *full = zsig_names[i].name;
		const char *shortn = full;
		if (strncmp(full, "SIG", 3) == 0)
			shortn = full + 3;
		if (ieq(buf, full) || ieq(buf, shortn)) {
			*sigp = zsig_names[i].num;
			return 0;
		}
	}
	return -1;
}

static void
set_default(struct zsig_table *zt, int sig, int stop, int pass, int print)
{
	if (sig <= 0 || sig >= ZDBG_MAX_SIGNALS)
		return;
	zt->sig[sig].stop = stop ? ZSIG_YES : ZSIG_NO;
	zt->sig[sig].pass = pass ? ZSIG_YES : ZSIG_NO;
	zt->sig[sig].print = print ? ZSIG_YES : ZSIG_NO;
}

void
zsig_table_init(struct zsig_table *zt)
{
	size_t i;

	if (zt == NULL)
		return;
	memset(zt, 0, sizeof(*zt));

	/* Start with "stop yes, pass yes, print yes" for every known
	 * signal.  Then override the specifically-tuned entries. */
	for (i = 0; i < zsig_names_n; i++) {
		int s = zsig_names[i].num;
		if (s <= 0 || s >= ZDBG_MAX_SIGNALS)
			continue;
		zt->sig[s].stop = ZSIG_YES;
		zt->sig[s].pass = ZSIG_YES;
		zt->sig[s].print = ZSIG_YES;
	}

	/* SIGTRAP is debugger-internal most of the time. */
	set_default(zt, 5,  1, 0, 0);   /* SIGTRAP */
	/* SIGSTOP: stop yes, pass no (we inject SIGSTOPs internally). */
	set_default(zt, 19, 1, 0, 1);   /* SIGSTOP */
	/* Noise: SIGCHLD / SIGWINCH should auto-continue silently. */
	set_default(zt, 17, 0, 1, 0);   /* SIGCHLD */
	set_default(zt, 28, 0, 1, 0);   /* SIGWINCH */
}

const struct zsig_policy *
zsig_get_policy(const struct zsig_table *zt, int sig)
{
	if (zt == NULL || sig <= 0 || sig >= ZDBG_MAX_SIGNALS)
		return NULL;
	return &zt->sig[sig];
}

int
zsig_set_policy(struct zsig_table *zt, int sig,
    int set_stop, int stop,
    int set_pass, int pass,
    int set_print, int print)
{
	if (zt == NULL || sig <= 0 || sig >= ZDBG_MAX_SIGNALS)
		return -1;
	if (set_stop)
		zt->sig[sig].stop = stop ? ZSIG_YES : ZSIG_NO;
	if (set_pass)
		zt->sig[sig].pass = pass ? ZSIG_YES : ZSIG_NO;
	if (set_print)
		zt->sig[sig].print = print ? ZSIG_YES : ZSIG_NO;
	return 0;
}

void
zsig_print_one(int sig, const struct zsig_policy *p)
{
	if (p == NULL)
		return;
	printf(" %-9s %-4s %-4s %-4s\n", zsig_name(sig),
	    p->stop  ? "yes" : "no",
	    p->pass  ? "yes" : "no",
	    p->print ? "yes" : "no");
}

void
zsig_print_table(const struct zsig_table *zt)
{
	size_t i;

	if (zt == NULL)
		return;
	printf(" Signal    Stop Pass Print\n");
	for (i = 0; i < zsig_names_n; i++) {
		int s = zsig_names[i].num;
		if (s <= 0 || s >= ZDBG_MAX_SIGNALS)
			continue;
		zsig_print_one(s, &zt->sig[s]);
	}
}
