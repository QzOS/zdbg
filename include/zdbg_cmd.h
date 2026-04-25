/*
 * zdbg_cmd.h - command dispatch and REPL interface.
 */

#ifndef ZDBG_CMD_H
#define ZDBG_CMD_H

#include <stdio.h>

#include "zdbg.h"
#include "zdbg_target.h"
#include "zdbg_bp.h"
#include "zdbg_hwbp.h"
#include "zdbg_regs.h"
#include "zdbg_maps.h"
#include "zdbg_signal.h"
#include "zdbg_exception.h"
#include "zdbg_symbols.h"
#include "zdbg_patch.h"

struct zdbg {
	struct ztarget target;
	struct zbp_table bps;
	struct zhwbp_table hwbps;
	struct zregs regs;
	struct zmap_table maps;
	struct zmap_table regions;
	struct zsym_table syms;
	struct zsig_table sigs;
	struct zexc_table excs;
	struct zpatch_table patches;
	zaddr_t dump_addr;
	zaddr_t asm_addr;
	int have_regs;
	int have_maps;
	int have_regions;
	int have_syms;
	int target_argc;
	char **target_argv;
	int stopped_bp;		/* id of breakpoint currently stopped on, -1 otherwise */
	int stopped_hwbp;	/* id of hw breakpoint currently stopped on, -1 otherwise */
	/*
	 * Most recent user-visible stop, used by script-friendly
	 * `check` assertions.  `have_last_stop` is 0 until at least
	 * one stop has been observed (initial trap, breakpoint,
	 * single-step, signal, exception, or exit).  Cleared when
	 * the target is detached/killed.
	 */
	struct zstop last_stop;
	int have_last_stop;
	int last_stop_hwbp;	/* hwbp slot id for the recorded stop, -1 otherwise */
	int last_stop_is_watch;	/* nonzero when last hw stop is a data watchpoint */
	/* Script / batch / REPL execution state. */
	int quit_requested;	/* set by `q`/`quit` to ask the REPL or */
				/* script driver to stop reading commands. */
	int had_error;		/* sticky: any command has failed since reset. */
	int last_status;	/* return value of the most recent command. */
	int source_depth;	/* current `source` nesting depth. */
	int verbose;		/* echo script commands before executing. */
	int quiet;		/* suppress banner and prompts. */
};

#define ZDBG_MAX_SOURCE_DEPTH 8
#define ZDBG_SCRIPT_LINE_MAX  1024

void zdbg_init(struct zdbg *d);
void zdbg_fini(struct zdbg *d);
int  zcmd_exec(struct zdbg *d, const char *line);
int  zrepl_run(struct zdbg *d);

/*
 * Execute the line-oriented command script at `path`.  Blank
 * lines and full-line comments beginning with `;` or `#` after
 * leading whitespace are skipped.  Each remaining line is run
 * with zcmd_exec().  By default execution stops at the first
 * failing command and the failing return value is propagated.
 *
 * Returns 0 on success, -1 on a command failure, and -2 on
 * setup/file-open failure (file missing, line too long, source
 * nesting too deep).  Sets d->had_error on command failures.
 * If `q` is encountered the function stops and returns 0 with
 * d->quit_requested set.
 */
int  zcmd_source_file(struct zdbg *d, const char *path);

/*
 * Like zcmd_source_file() but reads from an already-open
 * stream.  `name` is used in diagnostics (e.g. "<stdin>").
 */
int  zcmd_source_stream(struct zdbg *d, FILE *fp, const char *name);

/*
 * Quote-aware token splitter.  Reads `line`, copies tokens into
 * `buf` (capacity `buflen` bytes) as a sequence of NUL-terminated
 * strings, and stores pointers to each into argv[0..*argcp-1] up
 * to `maxargv`.  Honors whitespace separators and "double-quoted"
 * segments: quotes are stripped, and inside quotes a backslash
 * escapes the next character literally so escape sequences such
 * as \" and \\ survive into the caller for later interpretation.
 *
 * Returns 0 on success.  Returns -1 if argv would overflow
 * (`maxargv`) or if buf would overflow (`buflen`).
 */
int  zcmd_split_quoted(const char *line, char *buf, size_t buflen,
    char **argv, int maxargv, int *argcp);

#endif /* ZDBG_CMD_H */
