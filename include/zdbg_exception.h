/*
 * zdbg_exception.h - Windows exception name parsing/formatting
 * and the stop/pass/print policy table used by the `handle` and
 * `ex` commands.
 *
 * This layer is platform-neutral on purpose: it just talks about
 * Windows exception codes (sparse 32-bit values) and three
 * boolean flags.  The Windows backend is responsible for mapping
 * these codes to the pending DEBUG_EVENT continuation status via
 * the target API (ztarget_{get,set,clear}_pending_exception).
 *
 * Terminology:
 *   pass     -> continue with DBG_EXCEPTION_NOT_HANDLED
 *   nopass   -> continue with DBG_CONTINUE (exception handled)
 *   stop     -> return to prompt when the exception occurs
 *   nostop   -> apply pass/nopass policy and auto-continue
 *   print    -> print exception stop line
 *   noprint  -> do not print when nostop auto-continues
 *
 * pass=yes on Windows mirrors pass=yes on Linux: the fault is
 * delivered to the target's own handling.  pass=no is dangerous
 * but useful for suppressing noisy first-chance exceptions.
 */

#ifndef ZDBG_EXCEPTION_H
#define ZDBG_EXCEPTION_H

#include <stdint.h>

#include "zdbg.h"

/*
 * Maximum number of policy slots.  Windows exception codes are
 * sparse 32-bit values, so this table stores them by code
 * rather than indexing directly.
 */
#define ZDBG_MAX_EXCEPTIONS 128

enum zexc_domain {
	ZEXC_DOMAIN_WINDOWS = 1
};

struct zexc_policy {
	uint32_t code;	/* 0 in unused slots / in defpol sentinel */
	int stop;
	int pass;
	int print;
};

struct zexc_table {
	struct zexc_policy pol[ZDBG_MAX_EXCEPTIONS];
	int count;
	struct zexc_policy defpol;	/* policy for unknown codes */
};

/* Initialize every slot with the recommended default policy. */
void zexc_table_init(struct zexc_table *xt);

/*
 * "EXCEPTION_ACCESS_VIOLATION" for 0xc0000005, "EXCEPTION?" for
 * unknown codes.  Always non-NULL.
 */
const char *zexc_name(uint32_t code);

/*
 * Parse a user-supplied exception name or numeric code into a
 * 32-bit Windows exception code.  Accepts the full Win32 macro
 * name, the short form ("access_violation"), a few small
 * aliases ("av", "cpp", "msvc_cpp"), hex with or without 0x
 * prefix, and "#N" for explicit decimal.  Returns 0 on success
 * and -1 on failure.  Leading/trailing whitespace is tolerated.
 */
int zexc_parse(const char *s, uint32_t *codep);

/*
 * Look up a per-code policy.  Returns a pointer to the slot if
 * the code has an explicit policy, otherwise a pointer to the
 * table default (so callers always get a non-NULL policy for a
 * non-NULL table).
 */
const struct zexc_policy *zexc_get_policy(const struct zexc_table *xt,
    uint32_t code);

/*
 * Update selected fields of a code's policy.  The set_* flags
 * indicate which of stop/pass/print should be applied; the
 * matching stop/pass/print value is then written.  If the code
 * is not present in the table yet, a new slot is created (up to
 * ZDBG_MAX_EXCEPTIONS).  Returns 0 on success, -1 on overflow.
 */
int zexc_set_policy(struct zexc_table *xt, uint32_t code,
    int set_stop, int stop,
    int set_pass, int pass,
    int set_print, int print);

/* Print a single policy line.  p must be non-NULL. */
void zexc_print_one(uint32_t code, const struct zexc_policy *p);

/* Print a header followed by every known policy. */
void zexc_print_table(const struct zexc_table *xt);

/*
 * List every name known to zexc_parse/zexc_name, one per line,
 * "0xcccccccc NAME\n".  Used by `ex -l`.
 */
void zexc_print_names(void);

#endif /* ZDBG_EXCEPTION_H */
