/*
 * zdbg_signal.h - signal name parsing/formatting and the
 * stop/pass/print policy table used by the `handle` command.
 *
 * This layer is OS-neutral on purpose.  It just talks about
 * signal numbers and three boolean flags; the Linux backend is
 * responsible for mapping these numbers to per-thread pending
 * signal state via the target API (ztarget_{get,set}_pending_signal).
 */

#ifndef ZDBG_SIGNAL_H
#define ZDBG_SIGNAL_H

#include "zdbg.h"

#define ZDBG_MAX_SIGNALS 128

enum zsig_tri {
	ZSIG_NO = 0,
	ZSIG_YES = 1
};

struct zsig_policy {
	int stop;
	int pass;
	int print;
};

struct zsig_table {
	struct zsig_policy sig[ZDBG_MAX_SIGNALS];
};

/* Initialize every slot to safe defaults. */
void zsig_table_init(struct zsig_table *zt);

/* "SIGSEGV" for 11, "SIG?" for unknown.  Always non-NULL. */
const char *zsig_name(int sig);

/*
 * Parse "SIGSEGV", "SEGV", "11", "#11" or "0xb" into a signal
 * number.  Leading/trailing whitespace is tolerated.  Returns
 * 0 on success and -1 on failure.  *sigp is only written on
 * success.  The zero signal is valid (means "no signal").
 */
int zsig_parse(const char *s, int *sigp);

/*
 * Print a single policy line, "SIGSEGV   yes   yes   yes".
 */
void zsig_print_one(int sig, const struct zsig_policy *p);

/*
 * Print a header followed by every known non-empty policy.
 */
void zsig_print_table(const struct zsig_table *zt);

/*
 * Update selected fields of a policy.  The set_* flags indicate
 * which of stop/pass/print should be applied; the matching
 * stop/pass/print value is then written.  Returns 0 on success,
 * -1 if sig is out of range.
 */
int zsig_set_policy(struct zsig_table *zt, int sig,
    int set_stop, int stop,
    int set_pass, int pass,
    int set_print, int print);

/* Accessor for the policy of a single signal number.  Returns
 * NULL when sig is out of range. */
const struct zsig_policy *zsig_get_policy(const struct zsig_table *zt,
    int sig);

#endif /* ZDBG_SIGNAL_H */
