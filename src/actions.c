/*
 * actions.c - bounded action lists for breakpoints/watchpoints.
 *
 * Pure data + a small allow-list of command names.  Execution
 * lives in cmd.c where it can dispatch through zcmd_exec().
 * Storing a constant list of permitted first-token names here
 * keeps the policy in one place and lets the command layer
 * reject obviously unsafe action lines without duplicating
 * implementations.
 */

#include <ctype.h>
#include <string.h>

#include "zdbg_actions.h"

void
zactions_init(struct zaction_list *a)
{
	if (a == NULL)
		return;
	memset(a, 0, sizeof(*a));
}

void
zactions_clear(struct zaction_list *a)
{
	if (a == NULL)
		return;
	memset(a, 0, sizeof(*a));
}

int
zactions_add(struct zaction_list *a, const char *line)
{
	size_t n;

	if (a == NULL || line == NULL)
		return -1;
	if (a->count >= ZDBG_MAX_ACTIONS)
		return -1;
	n = strlen(line);
	if (n == 0)
		return -1;
	if (n >= ZDBG_ACTION_LINE_MAX)
		return -1;
	memcpy(a->lines[a->count], line, n);
	a->lines[a->count][n] = 0;
	a->count++;
	return 0;
}

int
zactions_del(struct zaction_list *a, int index)
{
	int i;

	if (a == NULL)
		return -1;
	if (index < 0 || index >= a->count)
		return -1;
	for (i = index; i < a->count - 1; i++)
		memcpy(a->lines[i], a->lines[i + 1], ZDBG_ACTION_LINE_MAX);
	memset(a->lines[a->count - 1], 0, ZDBG_ACTION_LINE_MAX);
	a->count--;
	return 0;
}

int
zactions_set(struct zaction_list *a, int index, const char *line)
{
	size_t n;

	if (a == NULL || line == NULL)
		return -1;
	if (index < 0 || index >= a->count)
		return -1;
	n = strlen(line);
	if (n == 0)
		return -1;
	if (n >= ZDBG_ACTION_LINE_MAX)
		return -1;
	memcpy(a->lines[index], line, n);
	a->lines[index][n] = 0;
	return 0;
}

void
zactions_set_silent(struct zaction_list *a, int silent)
{
	if (a == NULL)
		return;
	a->silent = silent ? 1 : 0;
}

/*
 * Skip leading ASCII whitespace.  Returns the adjusted pointer.
 */
static const char *
skip_ws(const char *p)
{
	if (p == NULL)
		return NULL;
	while (*p == ' ' || *p == '\t')
		p++;
	return p;
}

/*
 * Compare lowercased token at `p` (length `len`) against `kw`.
 * Returns nonzero on case-insensitive match.
 */
static int
tok_eq(const char *p, size_t len, const char *kw)
{
	size_t i;

	if (strlen(kw) != len)
		return 0;
	for (i = 0; i < len; i++) {
		char a = (char)tolower((unsigned char)p[i]);
		char b = (char)tolower((unsigned char)kw[i]);
		if (a != b)
			return 0;
	}
	return 1;
}

/*
 * Extract the first whitespace-separated token of `line`.
 * Returns a pointer to its start (may equal `line` skipped over
 * leading whitespace) and writes its length into *lenp.  Returns
 * NULL when `line` has no token.
 */
static const char *
first_token(const char *line, size_t *lenp)
{
	const char *p;
	const char *start;

	if (line == NULL || lenp == NULL)
		return NULL;
	p = skip_ws(line);
	if (*p == 0)
		return NULL;
	start = p;
	while (*p && *p != ' ' && *p != '\t')
		p++;
	*lenp = (size_t)(p - start);
	return start;
}

int
zactions_is_continue(const char *line)
{
	const char *tok;
	size_t len = 0;

	tok = first_token(line, &len);
	if (tok == NULL)
		return 0;
	return tok_eq(tok, len, "continue") || tok_eq(tok, len, "cont");
}

/*
 * Allow-list of commands legal inside an action list.  Action
 * lists run while the target is stopped inside the breakpoint
 * handling path; this list is the set that can safely
 * inspect/log/check.  Anything that mutates breakpoints,
 * patches, signals, exception policy, the target program, or
 * recursively starts a wait must not appear here.
 */
static const char *const allowed_cmds[] = {
	"r",
	"u",
	"d",
	"x",
	"addr",
	"bt",
	"lm",
	"sym",
	"th",
	"pl",
	"hl",
	"b",
	"hits",
	"check",
	"assert",
	"expect",
	"printf",
	"print",
	"eval",
	"silent",
	"continue",
	"cont",
	NULL
};

int
zactions_is_allowed(const char *line)
{
	const char *tok;
	const char *after;
	size_t len = 0;
	int i;

	tok = first_token(line, &len);
	if (tok == NULL)
		return 0;
	for (i = 0; allowed_cmds[i] != NULL; i++) {
		if (tok_eq(tok, len, allowed_cmds[i])) {
			/*
			 * `b` is permitted only as a list command:
			 * `b ADDR` would create a new breakpoint and
			 * is rejected to avoid mid-stop mutation.
			 */
			if (tok_eq(tok, len, "b")) {
				after = skip_ws(tok + len);
				if (*after != 0)
					return 0;
			}
			return 1;
		}
	}
	return 0;
}
