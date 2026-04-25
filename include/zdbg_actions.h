/*
 * zdbg_actions.h - bounded action lists attached to a software
 * or hardware breakpoint/watchpoint.
 *
 * An action list is a fixed-size, line-oriented sequence of
 * commands that runs while the target is stopped at a hit, after
 * the stop filter (hits/ignore/condition) has decided that the
 * hit is user-visible.  It is deliberately not a scripting
 * language: there are no variables, loops, conditionals, or
 * macros, and only an explicit allow-listed subset of commands
 * may appear in an action.
 *
 * The `silent` flag suppresses the normal stop output for that
 * hit so tracepoint-style "log and continue" workflows produce
 * only the lines they print themselves.  The special `continue`
 * (alias `cont`) action does not run as a normal command; it
 * sets a flag so the outer hit handler resumes the target via
 * the same restore/single-step/reinsert path used by ignored
 * hits, instead of recursively invoking `g`.
 *
 * The data structure is pure data so it can be unit-tested
 * without bringing in `struct zdbg`; execution lives in cmd.c.
 */

#ifndef ZDBG_ACTIONS_H
#define ZDBG_ACTIONS_H

#include <stddef.h>

#define ZDBG_MAX_ACTIONS      8
#define ZDBG_ACTION_LINE_MAX  160

struct zaction_list {
	int count;
	int silent;
	char lines[ZDBG_MAX_ACTIONS][ZDBG_ACTION_LINE_MAX];
};

void zactions_init(struct zaction_list *a);
void zactions_clear(struct zaction_list *a);

/*
 * Append a copy of `line` to `a`.  Returns 0 on success, -1 if
 * `a` is full or `line` does not fit in ZDBG_ACTION_LINE_MAX.
 * NULL or empty `line` is rejected with -1.  The line is stored
 * verbatim (no trimming, no escape interpretation).
 */
int  zactions_add(struct zaction_list *a, const char *line);

/*
 * Remove the action at `index` (0-based).  Later actions shift
 * down by one slot.  Returns 0 on success, -1 on out-of-range.
 */
int  zactions_del(struct zaction_list *a, int index);

/*
 * Replace the action at `index`.  Returns 0 on success, -1 on
 * out-of-range or when `line` does not fit.
 */
int  zactions_set(struct zaction_list *a, int index, const char *line);

void zactions_set_silent(struct zaction_list *a, int silent);

/*
 * Return nonzero when `line` is the special `continue` / `cont`
 * action.  Whitespace before/after the keyword is tolerated.
 */
int  zactions_is_continue(const char *line);

/*
 * Return nonzero when the first whitespace-separated token of
 * `line` is in the allow-list of commands that may appear in an
 * action list.  The check is case-insensitive.  Empty input is
 * rejected.
 */
int  zactions_is_allowed(const char *line);

#endif /* ZDBG_ACTIONS_H */
