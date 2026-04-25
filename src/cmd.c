/*
 * cmd.c - command parser and dispatcher.
 *
 * The REPL (repl.c) reads a line and calls zcmd_exec() with it.
 * Every individual command handler lives here, keeping the
 * parsing layer isolated from both the REPL and the backends.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

#include "zdbg.h"
#include "zdbg_cmd.h"
#include "zdbg_expr.h"
#include "zdbg_hwbp.h"
#include "zdbg_maps.h"
#include "zdbg_mem.h"
#include "zdbg_regs.h"
#include "zdbg_signal.h"
#include "zdbg_exception.h"
#include "zdbg_symbols.h"
#include "zdbg_target.h"
#include "zdbg_tinyasm.h"
#include "zdbg_tinydis.h"
#include "zdbg_patch.h"
#include "zdbg_filter.h"
#include "zdbg_actions.h"

#define RC_QUIT 1

/* tiny token splitter: dup the line and split on whitespace */
#define MAX_TOKENS 8

struct toks {
	char buf[256];
	char *v[MAX_TOKENS];
	int n;
	const char *rest; /* points into buf; remainder after tokens */
	const char *orig; /* original input line */
};

static void
tokenize(const char *line, struct toks *t)
{
	size_t n;
	char *p;
	int i;

	t->n = 0;
	t->rest = "";
	t->orig = line;
	n = strlen(line);
	if (n >= sizeof(t->buf))
		n = sizeof(t->buf) - 1;
	memcpy(t->buf, line, n);
	t->buf[n] = 0;

	p = t->buf;
	for (i = 0; i < MAX_TOKENS; i++) {
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == 0)
			break;
		t->v[t->n++] = p;
		while (*p && *p != ' ' && *p != '\t')
			p++;
		if (*p == 0)
			break;
		*p++ = 0;
	}
	while (*p == ' ' || *p == '\t')
		p++;
	t->rest = p;
}

/*
 * Return the remainder of the original input line starting at
 * the Nth whitespace-separated token.  This is needed because
 * tokenize() already cut the line into NUL-terminated words.
 */
static const char *
rest_from(const char *line, int which)
{
	const char *p = line;
	int seen = 0;

	while (*p == ' ' || *p == '\t')
		p++;
	while (*p && seen < which) {
		while (*p && *p != ' ' && *p != '\t')
			p++;
		while (*p == ' ' || *p == '\t')
			p++;
		seen++;
	}
	return p;
}

static void
to_lower(char *s)
{
	for (; *s; s++)
		*s = (char)tolower((unsigned char)*s);
}

static void
print_help(void)
{
	printf("commands:\n"
	    "  ?                    show this help\n"
	    "  q                    quit\n"
	    "  l [path [args...]]   launch target\n"
	    "  la pid               attach to pid\n"
	    "  ld                   detach from target\n"
	    "  k                    kill target\n"
	    "  r [reg [value]]      show/set register value\n"
	    "  d [addr [len]]       dump memory\n"
	    "  x [addr [len]]       alias for d\n"
	    "  e addr bytes...      write bytes\n"
	    "  f addr len bytes...  fill memory\n"
	    "  s addr len bytes...  search explicit range for bytes\n"
	    "  s -a|-r pattern      search all readable regions\n"
	    "  s -m module pattern  search one module range\n"
	    "  s -str|-wstr|-u32|-u64|-ptr ...\n"
	    "                       string/integer/pointer pattern forms\n"
	    "  c addr1 len addr2    compare two memory ranges\n"
	    "  m src len dst        copy/move memory inside target (journaled)\n"
	    "  wf addr len path     write target memory range to host file\n"
	    "  rf path addr [len]   read host file bytes into target (journaled)\n"
	    "  u [addr [count]]     tiny unassemble\n"
	    "  a [addr]             interactive tiny assemble\n"
	    "  pa addr len insn     patch instruction + NOP fill\n"
	    "  ij addr              invert jz/jnz at addr\n"
	    "  pl                   list recorded patches\n"
	    "  pu id|*              undo/revert patch(es) in live memory\n"
	    "  pr id|*              reapply reverted patch(es)\n"
	    "  pf id                show file mapping for patch\n"
	    "  ps id|* path         save patch bytes or patch script\n"
	    "  pw id|*              write applied patch(es) back to file\n"
	    "  b [addr]             list/set breakpoint\n"
	    "  bc n|*               clear breakpoint\n"
	    "  bd n                 disable breakpoint\n"
	    "  be n                 enable breakpoint\n"
	    "  hb addr              set hardware execute breakpoint\n"
	    "  hw addr len w|rw     set hardware data watchpoint\n"
	    "  hl                   list hardware breakpoints/watchpoints\n"
	    "  hc n|*               clear hardware breakpoint/watchpoint\n"
	    "  hd n                 disable hardware slot\n"
	    "  he n                 enable hardware slot\n"
	    "  cond b|h id expr     set breakpoint/watchpoint condition\n"
	    "  cond b|h id clear    clear condition\n"
	    "  ignore b|h id count  ignore next count hits\n"
	    "  hits b|h id [reset]  show/reset hit count\n"
	    "  actions b|h id [add LINE|del N|clear|silent on|off]\n"
	    "                       show/edit breakpoint action list\n"
	    "  trace b ADDR [TEXT]  create silent software tracepoint\n"
	    "  trace h ID [TEXT]    convert hwbp/watchpoint to tracepoint\n"
	    "  printf TEXT...       print literal text (\\n \\t \\xNN)\n"
	    "  lm [addr]            list maps or show map at addr\n"
	    "  sym [filter|-r]      list/search/refresh ELF symbols\n"
	    "  addr expr            show address, nearest symbol, mapping\n"
	    "  bt [count]           frame-pointer backtrace\n"
	    "  g                    continue\n"
	    "  t                    single step\n"
	    "  p                    proceed / step over direct call\n"
	    "  th [tid|index]       list/select traced thread\n"
	    "  sig [-l|0|name|num]  show/list/clear/set pending signal\n"
	    "  ex [-l|0|pass|nopass|code]\n"
	    "                       show/list/clear/set pending Windows "
	    "exception\n"
	    "  handle [sig [opts]]  show/set signal/exception stop/pass/"
	    "print policy\n"
	    "  source path          execute commands from script file\n"
	    "  . path                alias for source\n"
	    "  check ...            script-friendly assertion (see README)\n"
	    "  assert ...           alias for check\n");
}

static int
have_target(struct zdbg *d)
{
	return d->target.state != ZTARGET_EMPTY &&
	    d->target.state != ZTARGET_EXITED &&
	    d->target.state != ZTARGET_DETACHED;
}

static int
target_stopped(struct zdbg *d)
{
	return d->target.state == ZTARGET_STOPPED;
}

/*
 * Write " <symbol+off>" into buf if st has a symbol for addr.
 * On no match buf is left empty.  Output always NUL-terminated.
 */
static void
annot_addr(const struct zdbg *d, zaddr_t addr, char *buf, size_t buflen)
{
	char sbuf[ZDBG_SYM_NAME_MAX + ZDBG_SYM_MODULE_MAX + 32];
	int n;

	if (buf != NULL && buflen > 0)
		buf[0] = 0;
	if (d == NULL || !d->have_syms || buf == NULL || buflen == 0)
		return;
	n = zsyms_format_addr(&d->syms, addr, sbuf, sizeof(sbuf));
	if (n <= 0)
		return;
	snprintf(buf, buflen, " <%s>", sbuf);
}

/*
 * Build a "thread N" prefix when more than one traced thread is
 * known.  On single-threaded sessions buf is left empty so the
 * existing single-thread output is preserved.
 */
static void
stop_thread_prefix(struct zdbg *d, const struct zstop *st, char *buf,
    size_t buflen)
{
	int nth;

	if (buf == NULL || buflen == 0)
		return;
	buf[0] = 0;
	if (d == NULL || st == NULL)
		return;
	nth = ztarget_thread_count(&d->target);
	if (nth <= 1)
		return;
	if (st->tid == 0)
		return;
	snprintf(buf, buflen, "thread %llu ",
	    (unsigned long long)st->tid);
}

static void
zstop_print(const struct zdbg *d, const struct zstop *st, int bp_id)
{
	char ann[ZDBG_SYM_NAME_MAX + ZDBG_SYM_MODULE_MAX + 48];
	char tp[64];
	const char *reason = "stop";

	if (st == NULL)
		return;
	annot_addr(d, st->addr, ann, sizeof(ann));
	stop_thread_prefix((struct zdbg *)d, st, tp, sizeof(tp));
	/*
	 * If a hardware breakpoint/watchpoint fired, report it
	 * distinctly from software breakpoints.  d->stopped_hwbp
	 * is set by zdbg_after_wait before zstop_print is called.
	 * On Windows hardware traps arrive as EXCEPTION_SINGLE_STEP
	 * (mapped to ZSTOP_SINGLESTEP) so recognize that too.
	 */
	if ((st->reason == ZSTOP_BREAKPOINT ||
	    st->reason == ZSTOP_SINGLESTEP) && d != NULL &&
	    d->stopped_hwbp >= 0 &&
	    d->stopped_hwbp < ZDBG_MAX_HWBP) {
		const struct zhwbp *b = &d->hwbps.bp[d->stopped_hwbp];
		char aann[ZDBG_SYM_NAME_MAX + ZDBG_SYM_MODULE_MAX + 48];
		if (b->kind == ZHWBP_EXEC) {
			printf("stopped: %shardware breakpoint %d at %016llx%s\n",
			    tp, d->stopped_hwbp,
			    (unsigned long long)st->addr, ann);
			return;
		}
		annot_addr(d, b->addr, aann, sizeof(aann));
		printf("stopped: %swatchpoint %d %s addr=%016llx%s"
		    " rip=%016llx%s\n",
		    tp, d->stopped_hwbp,
		    b->kind == ZHWBP_WRITE ? "write" : "read/write",
		    (unsigned long long)b->addr, aann,
		    (unsigned long long)st->addr, ann);
		return;
	}
	switch (st->reason) {
	case ZSTOP_INITIAL:
		printf("stopped: %sinitial trap rip=%016llx%s\n",
		    tp, (unsigned long long)st->addr, ann);
		return;
	case ZSTOP_BREAKPOINT:
		if (bp_id >= 0)
			printf("stopped: %sbreakpoint %d at %016llx%s\n",
			    tp, bp_id, (unsigned long long)st->addr, ann);
		else
			printf("stopped: %sbreakpoint rip=%016llx%s\n",
			    tp, (unsigned long long)st->addr, ann);
		return;
	case ZSTOP_SINGLESTEP:
		printf("stopped: %ssingle-step rip=%016llx%s\n",
		    tp, (unsigned long long)st->addr, ann);
		return;
	case ZSTOP_SIGNAL:
		printf("stopped: %ssignal %s(%d) rip=%016llx%s\n",
		    tp, zsig_name(st->code), st->code,
		    (unsigned long long)st->addr, ann);
		return;
	case ZSTOP_EXCEPTION: {
		const char *chance;
		const char *name;
		chance = st->first_chance ? " first-chance" : " second-chance";
		name = zexc_name((uint32_t)st->code);
		if (st->code != 0 && strcmp(name, "EXCEPTION?") != 0)
			printf("stopped: %sexception %s(0x%08x)%s"
			    " rip=%016llx%s\n",
			    tp, name, (unsigned int)st->code, chance,
			    (unsigned long long)st->addr, ann);
		else if (st->code != 0)
			printf("stopped: %sexception 0x%08x%s"
			    " rip=%016llx%s\n",
			    tp, (unsigned int)st->code, chance,
			    (unsigned long long)st->addr, ann);
		else
			printf("stopped: %sexception rip=%016llx%s\n",
			    tp, (unsigned long long)st->addr, ann);
		return;
	}
	case ZSTOP_EXIT:
		if (tp[0] != 0)
			printf("exited: %scode %d\n", tp, st->code);
		else
			printf("exited: code %d\n", st->code);
		return;
	case ZSTOP_ERROR:
		printf("stopped: error\n");
		return;
	case ZSTOP_NONE:
	default:
		printf("stopped: %s%s\n", tp, reason);
		return;
	}
}

/*
 * Refresh the cached register snapshot from the backend when a
 * target is stopped.  Silent on failure so the REPL keeps
 * working with stale values if the backend cannot produce
 * registers (e.g. non-x86-64 hosts).
 */
static void
refresh_regs(struct zdbg *d)
{
	if (!target_stopped(d))
		return;
	if (ztarget_getregs(&d->target, &d->regs) == 0)
		d->have_regs = 1;
}

/*
 * Lazily (re)read /proc/<pid>/maps for the current target.
 * Safe to call whether or not a target is active.
 */
static void
refresh_maps(struct zdbg *d)
{
	if (!have_target(d)) {
		d->have_maps = 0;
		d->maps.count = 0;
		return;
	}
	if (zmaps_refresh(&d->target, &d->maps) == 0)
		d->have_maps = 1;
	else
		d->have_maps = 0;
}

/*
 * Refresh the full memory-region view (Windows VirtualQueryEx
 * or Linux /proc/<pid>/maps).  Best effort; on hosts without a
 * region scanner this leaves d->have_regions = 0.
 */
static void
refresh_regions(struct zdbg *d)
{
	if (!have_target(d)) {
		d->have_regions = 0;
		d->regions.count = 0;
		return;
	}
	if (zmaps_refresh_regions(&d->target, &d->regions) == 0)
		d->have_regions = 1;
	else
		d->have_regions = 0;
}

/*
 * Forget the cached memory map.  Used on detach/kill/new launch.
 */
static void
clear_maps(struct zdbg *d)
{
	d->have_maps = 0;
	d->maps.count = 0;
	d->maps.truncated = 0;
	d->maps.main_hint[0] = 0;
	d->have_regions = 0;
	d->regions.count = 0;
	d->regions.truncated = 0;
	d->regions.main_hint[0] = 0;
}

/*
 * Refresh loaded ELF symbols from the current map table.  Safe
 * to call whether or not a target is active.
 */
static void
refresh_syms(struct zdbg *d)
{
	if (!have_target(d) || !d->have_maps) {
		zsyms_clear(&d->syms);
		d->have_syms = 0;
		return;
	}
	if (zsyms_refresh(&d->target, &d->maps, &d->syms) >= 0)
		d->have_syms = 1;
	else
		d->have_syms = 0;
}

static void
clear_syms(struct zdbg *d)
{
	zsyms_clear(&d->syms);
	d->have_syms = 0;
}

/*
 * Evaluate an address expression using the current cached
 * registers, memory map, and symbol table (if available).  If
 * maps have not yet been loaded but a live target exists, load
 * them lazily.  Returns 0 on success, -1 on failure.
 */
static int
eval_addr(struct zdbg *d, const char *s, zaddr_t *out)
{
	const struct zmap_table *maps;
	const struct zsym_table *syms;

	if (have_target(d) && !d->have_maps)
		refresh_maps(d);
	maps = d->have_maps ? &d->maps : NULL;
	syms = d->have_syms ? &d->syms : NULL;
	return zexpr_eval_symbols(s, &d->regs, maps, syms, out);
}

/* --- r --------------------------------------------------------- */
static int
cmd_r(struct zdbg *d, struct toks *t)
{
	if (t->n == 1) {
		refresh_regs(d);
		zregs_print(&d->regs);
		return 0;
	}
	if (t->n == 2) {
		uint64_t v = 0;
		refresh_regs(d);
		if (zregs_get_by_name(&d->regs, t->v[1], &v) < 0) {
			printf("unknown register: %s\n", t->v[1]);
			return -1;
		}
		printf("%s = %016llx\n", t->v[1], (unsigned long long)v);
		return 0;
	}
	if (t->n >= 3) {
		uint64_t v = 0;
		if (d->target.state == ZTARGET_RUNNING) {
			printf("target is running\n");
			return -1;
		}
		if (zexpr_eval(t->v[2], &d->regs, &v) < 0) {
			printf("bad value\n");
			return -1;
		}
		if (zregs_set_by_name(&d->regs, t->v[1], v) < 0) {
			printf("unknown register: %s\n", t->v[1]);
			return -1;
		}
		d->have_regs = 1;
		if (target_stopped(d)) {
			if (ztarget_setregs(&d->target, &d->regs) < 0) {
				printf("setregs failed\n");
				return -1;
			}
		}
		return 0;
	}
	return 0;
}

/* --- d / x ----------------------------------------------------- */
static int
cmd_d(struct zdbg *d, struct toks *t)
{
	zaddr_t addr = d->dump_addr;
	size_t len = 64;
	uint8_t buf[256];

	if (t->n >= 2) {
		if (eval_addr(d, t->v[1], &addr) < 0) {
			printf("bad address\n");
			return -1;
		}
	}
	if (t->n >= 3) {
		uint64_t v;
		if (zexpr_eval(t->v[2], &d->regs, &v) < 0 || v == 0) {
			printf("bad length\n");
			return -1;
		}
		len = (size_t)v;
	}
	if (len > sizeof(buf))
		len = sizeof(buf);

	if (!have_target(d) ||
	    ztarget_read(&d->target, addr, buf, len) < 0) {
		printf("target operation not available in this backend yet\n");
		return -1;
	}
	zmem_hexdump(addr, buf, len);
	d->dump_addr = addr + len;
	return 0;
}

/* --- patch journal helper -------------------------------------- */

/*
 * Central memory-write helper for user-initiated patch commands.
 *
 * Reads the current bytes at addr, writes the new bytes, flushes
 * the instruction cache, and records the change in d->patches
 * with the given origin string ("e", "f", "a", "pa", "ij").
 *
 * On successful record the patch id and address are printed.
 * File-backing is resolved from the current map table, but
 * writing to disk is always explicit (`pw`) and never implicit.
 *
 * Returns 0 on success, -1 on failure (with a message printed).
 */
static int
zdbg_patch_write(struct zdbg *d, zaddr_t addr, const void *new_bytes,
    size_t len, const char *origin)
{
	uint8_t oldb[ZDBG_PATCH_MAX_BYTES];
	int id;
	const struct zpatch *rec;
	int overlap;
	char ann[ZDBG_SYM_NAME_MAX + ZDBG_SYM_MODULE_MAX + 48];

	if (!have_target(d)) {
		printf("target operation not available in this backend yet\n");
		return -1;
	}
	if (!target_stopped(d)) {
		printf("no stopped target\n");
		return -1;
	}
	if (len == 0) {
		printf("empty patch\n");
		return -1;
	}
	if (len > ZDBG_PATCH_MAX_BYTES) {
		printf("patch too large to record; max %d bytes\n",
		    (int)ZDBG_PATCH_MAX_BYTES);
		return -1;
	}

	if (ztarget_read(&d->target, addr, oldb, len) < 0) {
		printf("read failed\n");
		return -1;
	}
	if (ztarget_write(&d->target, addr, new_bytes, len) < 0) {
		printf("write failed\n");
		return -1;
	}
	(void)ztarget_flush_icache(&d->target, addr, len);

	overlap = zpatch_find_overlap(&d->patches, addr, len);
	if (overlap >= 0)
		printf("warn: patch overlaps existing patch %d\n", overlap);

	id = zpatch_record(&d->patches, addr, oldb, new_bytes, len, origin);
	if (id < 0) {
		if (id == -2)
			printf("patch too large to record; max %d bytes\n",
			    (int)ZDBG_PATCH_MAX_BYTES);
		else
			printf("patch journal full\n");
		/* memory was still written; this is intentional */
		return 0;
	}
	/* file backing (optional) */
	if (have_target(d) && !d->have_maps)
		refresh_maps(d);
	if (d->have_maps)
		(void)zpatch_resolve_file(&d->patches.patches[id], &d->maps);

	if (zpatch_get(&d->patches, id, &rec) < 0)
		return 0;
	annot_addr(d, addr, ann, sizeof(ann));
	if (rec->has_file) {
		printf("patch %d %016llx len=%zu%s file=%s+0x%llx\n",
		    id, (unsigned long long)addr, len, ann,
		    rec->file, (unsigned long long)rec->file_off);
	} else {
		printf("patch %d %016llx len=%zu%s [no file backing]\n",
		    id, (unsigned long long)addr, len, ann);
	}
	return 0;
}

/* --- e --------------------------------------------------------- */
static int
cmd_e(struct zdbg *d, struct toks *t)
{
	zaddr_t addr;
	uint8_t buf[256];
	size_t blen = 0;

	if (t->n < 3) {
		printf("usage: e addr bytes...\n");
		return -1;
	}
	if (eval_addr(d, t->v[1], &addr) < 0) {
		printf("bad address\n");
		return -1;
	}
	if (zmem_parse_bytes(rest_from(t->orig, 2), buf, sizeof(buf),
	    &blen) < 0) {
		printf("bad bytes\n");
		return -1;
	}
	return zdbg_patch_write(d, addr, buf, blen, "e");
}

/* --- f --------------------------------------------------------- */
static int
cmd_f(struct zdbg *d, struct toks *t)
{
	zaddr_t addr;
	uint64_t len;
	uint8_t pat[64];
	uint8_t buf[256];
	size_t patlen = 0;
	size_t i;

	if (t->n < 4) {
		printf("usage: f addr len bytes...\n");
		return -1;
	}
	if (eval_addr(d, t->v[1], &addr) < 0) {
		printf("bad address\n");
		return -1;
	}
	if (zexpr_eval(t->v[2], &d->regs, &len) < 0 || len == 0) {
		printf("bad length\n");
		return -1;
	}
	/* bytes are t->v[3..], reconstruct from rest-of-line: rest
	 * points past the last token; we want tokens 3.. concatenated.
	 */
	{
		const char *byte_start = rest_from(t->orig, 3);
		if (zmem_parse_bytes(byte_start, pat, sizeof(pat), &patlen) < 0
		    || patlen == 0) {
			printf("bad bytes\n");
			return -1;
		}
	}
	if (len > sizeof(buf))
		len = sizeof(buf);
	for (i = 0; i < len; i++)
		buf[i] = pat[i % patlen];
	return zdbg_patch_write(d, addr, buf, (size_t)len, "f");
}

/* --- quote-aware splitter ------------------------------------- */

/*
 * Quote-aware re-tokenizer used by commands that need to keep
 * a quoted segment as a single argument: `s` (so
 * `s -str "hello world"` works) and the file-I/O commands `wf`
 * and `rf` (so paths with spaces survive).  Honors:
 *   - whitespace separators
 *   - "double-quoted" segments (kept as a single argument with
 *     quotes stripped); inside quotes a backslash escapes the
 *     next character literally so escape sequences like \" and
 *     \\ survive into any later interpreter (e.g. the search
 *     pattern builder, which interprets them itself).
 */
#define ZDBG_CMD_MAX_QARGS 32
#define ZDBG_CMD_QBUF_SIZE 512

struct cmd_qargs {
	char buf[ZDBG_CMD_QBUF_SIZE];
	char *v[ZDBG_CMD_MAX_QARGS];
	int n;
};

int
zcmd_split_quoted(const char *line, char *buf, size_t buflen,
    char **argv, int maxargv, int *argcp)
{
	char *out;
	const char *p;
	size_t cap;
	size_t used = 0;
	int n = 0;
	int c;

	if (line == NULL || buf == NULL || argv == NULL ||
	    argcp == NULL || buflen == 0 || maxargv <= 0)
		return -1;
	*argcp = 0;
	out = buf;
	cap = buflen;
	p = line;

	for (;;) {
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == 0)
			break;
		if (n >= maxargv)
			return -1;
		argv[n++] = out;
		while (*p && *p != ' ' && *p != '\t') {
			if (*p == '"') {
				p++;
				while (*p && *p != '"') {
					c = *p++;
					if (c == '\\' && *p) {
						/* Preserve the backslash and the next
						 * character literally so any pattern
						 * builder can interpret escapes. */
						if (used + 1 >= cap)
							return -1;
						*out++ = (char)c;
						used++;
						c = *p++;
					}
					if (used + 1 >= cap)
						return -1;
					*out++ = (char)c;
					used++;
				}
				if (*p == '"')
					p++;
			} else {
				if (used + 1 >= cap)
					return -1;
				*out++ = *p++;
				used++;
			}
		}
		if (used + 1 >= cap)
			return -1;
		*out++ = 0;
		used++;
	}
	*argcp = n;
	return 0;
}

static int
cmd_qsplit(const char *line, struct cmd_qargs *a)
{
	a->n = 0;
	return zcmd_split_quoted(line, a->buf, sizeof(a->buf),
	    a->v, ZDBG_CMD_MAX_QARGS, &a->n);
}

struct s_match_ctx {
	struct zdbg *d;
	int count;
	int limit;
	int verbose;
};

static void
s_print_match(struct zdbg *d, zaddr_t addr)
{
	char ann[ZDBG_SYM_NAME_MAX + ZDBG_SYM_MODULE_MAX + 48];
	const struct zmap *r = NULL;
	const struct zmap *m = NULL;
	const char *perms = "----";
	const char *mtype = "---";
	const char *region_name = NULL;

	annot_addr(d, addr, ann, sizeof(ann));
	if (d->have_regions)
		r = zmaps_find_by_addr(&d->regions, addr);
	if (d->have_maps)
		m = zmaps_find_by_addr(&d->maps, addr);
	if (r != NULL) {
		perms = r->perms;
		mtype = zmaps_mem_type_str(r->mem_type);
		region_name = r->name;
	} else if (m != NULL) {
		perms = m->perms;
		region_name = m->name;
	}
	printf("%016llx%s%s%s %s %s\n",
	    (unsigned long long)addr, ann,
	    region_name != NULL ? " " : "",
	    region_name != NULL ? region_name : "",
	    perms, mtype);
}

static int
s_match_cb(zaddr_t addr, void *arg)
{
	struct s_match_ctx *ctx = (struct s_match_ctx *)arg;

	s_print_match(ctx->d, addr);
	ctx->count++;
	if (ctx->limit > 0 && ctx->count >= ctx->limit) {
		printf("(result limit %d reached)\n", ctx->limit);
		return 1;
	}
	return 0;
}

/*
 * Search [start, end) of target memory for `pat` in chunks,
 * keeping `patlen-1` bytes of overlap so matches that straddle
 * a chunk boundary are still found.  When skip_failures is
 * non-zero a failed read advances past the failed window
 * instead of aborting; this is what region scans want.
 *
 * Returns 1 if the result-limit callback stopped the scan,
 * 0 on normal completion of this range, -1 on an unrecoverable
 * read error when skip_failures was 0.
 */
static int
s_search_range(struct zdbg *d, zaddr_t start, zaddr_t end,
    const uint8_t *pat, size_t patlen, struct s_match_ctx *ctx,
    int skip_failures)
{
	uint8_t buf[ZDBG_SEARCH_CHUNK];
	zaddr_t cur = start;

	if (patlen == 0 || patlen > sizeof(buf))
		return -1;
	if (end <= start)
		return 0;

	while (cur < end) {
		uint64_t remaining = (uint64_t)(end - cur);
		size_t want = sizeof(buf);
		int r;

		if ((uint64_t)want > remaining)
			want = (size_t)remaining;
		if (ztarget_read(&d->target, cur, buf, want) < 0) {
			if (!skip_failures)
				return -1;
			/* Skip this window.  Advance by want minus the
			 * usual overlap to keep progress monotonic. */
			if (want <= patlen)
				cur += want ? want : 1;
			else
				cur += want - (patlen - 1);
			continue;
		}
		r = zmem_search_buffer(cur, buf, want, pat, patlen,
		    s_match_cb, ctx);
		if (r < 0)
			return -1;
		if (r > 0)
			return 1;
		if (want <= patlen)
			break;
		/* Advance with overlap of patlen-1 to catch matches
		 * crossing chunk boundaries. */
		cur += want - (patlen - 1);
	}
	return 0;
}

/*
 * Region filter: returns nonzero when the region should be
 * scanned.  Honors guard-page skip and the optional -x/-w/-i
 * filters.  Reads need at least one of read/exec.
 */
static int
s_region_eligible(const struct zmap *r, int want_x, int want_w, int want_i)
{
	if (r->perms[3] == 'g')
		return 0; /* skip guard pages */
	if (want_i && r->mem_type != ZMAP_MEM_IMAGE)
		return 0;
	if (want_w) {
		if (r->perms[1] != 'w')
			return 0;
	}
	if (want_x) {
		if (r->perms[2] != 'x')
			return 0;
		return 1;
	}
	/* Default: readable regions only. */
	if (r->perms[0] != 'r')
		return 0;
	return 1;
}

static int
s_parse_uint(const char *s, uint64_t *out)
{
	if (s == NULL || *s == 0)
		return -1;
	/* Use the existing expression evaluator so callers can
	 * write 0x..., #N decimal, or plain hex.  No registers/
	 * symbols are needed for limit/value parsing. */
	return zexpr_eval(s, NULL, out);
}

/*
 * Parse one pattern selector starting at argv[*idxp].
 *
 * Recognized forms:
 *   -str "text"   ASCII bytes (with the same escape set as cmd_s)
 *   -wstr "text"  UTF-16LE bytes
 *   -u32  expr    4-byte little-endian, expr resolved with eval_addr
 *   -u64  expr    8-byte little-endian, expr resolved with eval_addr
 *   -ptr  expr    pointer-sized little-endian (currently 8 bytes)
 *
 * Returns:
 *    1  selector recognized and consumed; *idxp advanced past the
 *       value argument; *lenp set
 *    0  argv[*idxp] is not a recognized selector; nothing consumed
 *   -1  selector recognized but its argument was missing or
 *       invalid; an error message has already been printed
 *
 * Shared by cmd_s and cmd_check so the two stay in sync.
 */
static int
parse_pattern_selector(struct zdbg *d, char **argv, int argc, int *idxp,
    uint8_t *pat, size_t cap, size_t *lenp)
{
	const char *opt;
	int i;

	if (argv == NULL || idxp == NULL || pat == NULL || lenp == NULL)
		return -1;
	i = *idxp;
	if (i >= argc)
		return 0;
	opt = argv[i];
	if (opt == NULL || opt[0] != '-')
		return 0;

	if (strcmp(opt, "-str") == 0) {
		if (i + 1 >= argc) {
			printf("usage: -str \"text\"\n");
			return -1;
		}
		if (zmem_make_ascii_pattern(argv[i + 1], pat, cap, lenp) < 0
		    || *lenp == 0) {
			printf("bad string\n");
			return -1;
		}
		*idxp = i + 1;
		return 1;
	}
	if (strcmp(opt, "-wstr") == 0) {
		if (i + 1 >= argc) {
			printf("usage: -wstr \"text\"\n");
			return -1;
		}
		if (zmem_make_utf16le_pattern(argv[i + 1], pat, cap, lenp) < 0
		    || *lenp == 0) {
			printf("bad wstring\n");
			return -1;
		}
		*idxp = i + 1;
		return 1;
	}
	if (strcmp(opt, "-u32") == 0) {
		zaddr_t v;
		if (i + 1 >= argc || eval_addr(d, argv[i + 1], &v) < 0) {
			printf("bad -u32 value\n");
			return -1;
		}
		zmem_make_u32_pattern((uint32_t)v, pat, cap, lenp);
		*idxp = i + 1;
		return 1;
	}
	if (strcmp(opt, "-u64") == 0) {
		zaddr_t v;
		if (i + 1 >= argc || eval_addr(d, argv[i + 1], &v) < 0) {
			printf("bad -u64 value\n");
			return -1;
		}
		zmem_make_u64_pattern((uint64_t)v, pat, cap, lenp);
		*idxp = i + 1;
		return 1;
	}
	if (strcmp(opt, "-ptr") == 0) {
		zaddr_t v;
		if (i + 1 >= argc || eval_addr(d, argv[i + 1], &v) < 0) {
			printf("bad -ptr expression\n");
			return -1;
		}
		zmem_make_u64_pattern((uint64_t)v, pat, cap, lenp);
		*idxp = i + 1;
		return 1;
	}
	return 0;
}

/* --- s --------------------------------------------------------- */

static int
cmd_s(struct zdbg *d, struct toks *t)
{
	struct cmd_qargs a;
	uint8_t pat[ZDBG_SEARCH_MAX_PATTERN];
	size_t patlen = 0;
	int have_pat = 0;
	int mode_a = 0;       /* -a / -r */
	int mode_x = 0;
	int mode_w = 0;
	int mode_i = 0;
	const char *mod_name = NULL;
	int limit = ZDBG_SEARCH_DEFAULT_LIMIT;
	int i;
	struct s_match_ctx ctx;
	const char *bytes_start = NULL;
	const char *cmd_line;
	int explicit_range = 0;
	zaddr_t range_addr = 0;
	uint64_t range_len = 0;

	(void)t;
	cmd_line = rest_from(t->orig, 1);
	if (cmd_qsplit(cmd_line, &a) < 0) {
		printf("argument list too long\n");
		return -1;
	}
	if (!have_target(d)) {
		printf("no target\n");
		return -1;
	}

	for (i = 0; i < a.n; i++) {
		const char *opt = a.v[i];
		if (strcmp(opt, "-a") == 0 || strcmp(opt, "-r") == 0) {
			mode_a = 1;
		} else if (strcmp(opt, "-x") == 0) {
			mode_x = 1;
			mode_a = 1;
		} else if (strcmp(opt, "-w") == 0) {
			mode_w = 1;
			mode_a = 1;
		} else if (strcmp(opt, "-i") == 0) {
			mode_i = 1;
			mode_a = 1;
		} else if (strcmp(opt, "-m") == 0) {
			if (i + 1 >= a.n) {
				printf("usage: s -m module pattern\n");
				return -1;
			}
			mod_name = a.v[++i];
		} else if (strcmp(opt, "-limit") == 0) {
			uint64_t v;
			if (i + 1 >= a.n ||
			    s_parse_uint(a.v[i + 1], &v) < 0 || v == 0) {
				printf("bad -limit\n");
				return -1;
			}
			limit = (int)v;
			i++;
		} else if (strcmp(opt, "-str") == 0 ||
		    strcmp(opt, "-wstr") == 0 ||
		    strcmp(opt, "-u32") == 0 ||
		    strcmp(opt, "-u64") == 0 ||
		    strcmp(opt, "-ptr") == 0) {
			int rc = parse_pattern_selector(d, a.v, a.n, &i,
			    pat, sizeof(pat), &patlen);
			if (rc < 0)
				return -1;
			if (rc == 0) {
				printf("unknown option: %s\n", opt);
				return -1;
			}
			have_pat = 1;
		} else if (opt[0] == '-' && opt[1] != 0) {
			printf("unknown option: %s\n", opt);
			return -1;
		} else {
			/* First non-option positional.  In the legacy
			 * `s addr len bytes...` form this is the address;
			 * otherwise these are raw byte tokens. */
			if (!have_pat && !mode_a && mod_name == NULL &&
			    i + 1 < a.n) {
				/* Legacy form: addr len bytes... */
				uint64_t v;
				if (eval_addr(d, a.v[i], &range_addr) < 0) {
					printf("bad address\n");
					return -1;
				}
				if (zexpr_eval(a.v[i + 1], &d->regs, &v) < 0
				    || v == 0) {
					printf("bad length\n");
					return -1;
				}
				range_len = v;
				explicit_range = 1;
				i += 2;
				bytes_start = (i < a.n) ? a.v[i] : NULL;
			} else {
				bytes_start = a.v[i];
			}
			/* Collect remaining positional args as raw bytes,
			 * stopping at any further `-option` so things like
			 * `s addr len 90 90 -limit 2` keep working. */
			if (bytes_start != NULL) {
				char tmp[ZDBG_SEARCH_MAX_PATTERN * 4];
				size_t tlen = 0;
				int k;
				int stop = i;
				tmp[0] = 0;
				for (k = i; k < a.n; k++) {
					if (a.v[k][0] == '-' &&
					    a.v[k][1] != 0) {
						stop = k;
						break;
					}
					{
						size_t need;
						need = strlen(a.v[k]) + 2;
						if (tlen + need >= sizeof(tmp))
							break;
						if (tlen)
							tmp[tlen++] = ' ';
						memcpy(tmp + tlen, a.v[k],
						    strlen(a.v[k]));
						tlen += strlen(a.v[k]);
						tmp[tlen] = 0;
					}
					stop = k + 1;
				}
				if (zmem_parse_bytes(tmp, pat, sizeof(pat),
				    &patlen) < 0 || patlen == 0) {
					printf("bad bytes\n");
					return -1;
				}
				have_pat = 1;
				/* Continue option parsing after the byte run. */
				i = stop - 1;
				continue;
			}
			break;
		}
	}

	if (!have_pat) {
		printf("usage:\n"
		    "  s addr len bytes...\n"
		    "  s -a|-r [-x|-w|-i] pattern\n"
		    "  s -m module pattern\n"
		    "pattern: bytes... | -str \"text\" | -wstr \"text\" |"
		    " -u32 v | -u64 v | -ptr expr\n");
		return -1;
	}
	if (patlen > ZDBG_SEARCH_MAX_PATTERN) {
		printf("pattern too long\n");
		return -1;
	}

	ctx.d = d;
	ctx.count = 0;
	ctx.limit = limit;
	ctx.verbose = 0;

	/* Refresh maps/regions/symbols opportunistically so
	 * annotation works the same way as `addr`/`lm`. */
	refresh_maps(d);
	refresh_regions(d);
	refresh_syms(d);

	/* --- explicit range -------------------------------------- */
	if (explicit_range) {
		if (s_search_range(d, range_addr, range_addr + range_len,
		    pat, patlen, &ctx, 0) < 0) {
			printf("read failed at %016llx\n",
			    (unsigned long long)range_addr);
			return -1;
		}
		if (ctx.count == 0)
			printf("no matches\n");
		return 0;
	}

	/* --- module-relative search ------------------------------ */
	if (mod_name != NULL) {
		const struct zmap *m;
		int amb = 0;
		if (!d->have_maps) {
			printf("no module table\n");
			return -1;
		}
		m = zmaps_find_module(&d->maps, mod_name, &amb);
		if (m == NULL) {
			printf("%s module: %s\n",
			    amb ? "ambiguous" : "unknown", mod_name);
			return -1;
		}
		(void)s_search_range(d, m->start, m->end, pat, patlen,
		    &ctx, 1);
		if (ctx.count == 0)
			printf("no matches\n");
		return 0;
	}

	/* --- region search --------------------------------------- */
	if (mode_a || (!explicit_range && mod_name == NULL)) {
		const struct zmap_table *mt = NULL;
		int searched = 0;
		int skipped = 0;
		int j;

		if (d->have_regions && d->regions.count > 0)
			mt = &d->regions;
		else if (d->have_maps)
			mt = &d->maps;
		if (mt == NULL) {
			printf("no regions available\n");
			return -1;
		}
		for (j = 0; j < mt->count; j++) {
			const struct zmap *r = &mt->maps[j];
			int rc;

			if (!s_region_eligible(r, mode_x, mode_w, mode_i))
				continue;
			searched++;
			rc = s_search_range(d, r->start, r->end, pat, patlen,
			    &ctx, 1);
			if (rc > 0)
				break; /* limit reached */
			if (rc < 0)
				skipped++;
		}
		printf("searched %d region(s), %d match(es)%s\n",
		    searched, ctx.count,
		    skipped ? " (some pages unreadable)" : "");
		return 0;
	}

	printf("usage: s addr len bytes... | s -a|-m|-r ... pattern\n");
	return -1;
}

/* --- memio (c, m, wf, rf) helpers ----------------------------- */

#define ZDBG_MEMIO_CHUNK    65536
#define ZDBG_C_DEFAULT_LIMIT 128

/*
 * Chunked patch-write helper used by `m` and `rf`.  Splits the
 * write into pieces no larger than ZDBG_PATCH_MAX_BYTES, reading
 * each old-byte chunk from the target before recording it in the
 * patch journal so each step is independently undoable.
 *
 * On success returns 0 and sets *written_out to len.  On a
 * read/write failure returns -1 and *written_out is the number
 * of bytes successfully written before the failure (so callers
 * can report a partial failure).  When the patch journal becomes
 * full mid-stream the helper stops and returns 1, again with
 * *written_out set to the byte count written so far.  The
 * instruction cache is flushed for each successfully-written
 * chunk.
 *
 * The helper deliberately does not print per-chunk status; the
 * caller renders one summary line at the end.
 */
static int
zdbg_patch_write_chunked(struct zdbg *d, zaddr_t addr,
    const uint8_t *buf, size_t len, const char *origin,
    size_t *written_out)
{
	size_t off = 0;

	if (written_out != NULL)
		*written_out = 0;
	if (!have_target(d) || !target_stopped(d) || len == 0)
		return -1;

	while (off < len) {
		size_t chunk = len - off;
		uint8_t oldb[ZDBG_PATCH_MAX_BYTES];
		int id;
		int overlap;

		if (chunk > ZDBG_PATCH_MAX_BYTES)
			chunk = ZDBG_PATCH_MAX_BYTES;

		if (ztarget_read(&d->target, addr + off, oldb, chunk) < 0)
			return -1;
		if (ztarget_write(&d->target, addr + off, buf + off,
		    chunk) < 0)
			return -1;
		(void)ztarget_flush_icache(&d->target, addr + off, chunk);

		overlap = zpatch_find_overlap(&d->patches, addr + off, chunk);
		if (overlap >= 0)
			printf("warn: patch overlaps existing patch %d\n",
			    overlap);

		id = zpatch_record(&d->patches, addr + off, oldb,
		    buf + off, chunk, origin);
		if (id < 0) {
			/* Journal full.  The bytes were already written;
			 * we report partial progress so the caller can
			 * decide whether to roll forward unjournaled
			 * (rf intentionally does not). */
			off += chunk;
			if (written_out != NULL)
				*written_out = off;
			return 1;
		}
		if (have_target(d) && !d->have_maps)
			refresh_maps(d);
		if (d->have_maps)
			(void)zpatch_resolve_file(
			    &d->patches.patches[id], &d->maps);

		off += chunk;
	}
	if (written_out != NULL)
		*written_out = off;
	return 0;
}

/* --- c addr1 len addr2 ---------------------------------------- */
static int
cmd_c(struct zdbg *d, struct toks *t)
{
	struct cmd_qargs a;
	const char *cmd_line;
	int i;
	int limit = ZDBG_C_DEFAULT_LIMIT;
	zaddr_t a1 = 0, a2 = 0;
	uint64_t len = 0;
	int have_a1 = 0, have_len = 0, have_a2 = 0;
	uint8_t b1[ZDBG_MEMIO_CHUNK];
	uint8_t b2[ZDBG_MEMIO_CHUNK];
	uint64_t off;
	int diffs = 0;
	int hit_limit = 0;

	cmd_line = rest_from(t->orig, 1);
	if (cmd_qsplit(cmd_line, &a) < 0) {
		printf("argument list too long\n");
		return -1;
	}
	for (i = 0; i < a.n; i++) {
		const char *opt = a.v[i];
		if (strcmp(opt, "-limit") == 0) {
			uint64_t v;
			if (i + 1 >= a.n ||
			    zexpr_eval(a.v[i + 1], NULL, &v) < 0 ||
			    v == 0 || v > (uint64_t)INT_MAX) {
				printf("bad -limit\n");
				return -1;
			}
			limit = (int)v;
			i++;
		} else if (opt[0] == '-' && opt[1] != 0) {
			printf("unknown option: %s\n", opt);
			return -1;
		} else if (!have_a1) {
			if (eval_addr(d, opt, &a1) < 0) {
				printf("bad address\n");
				return -1;
			}
			have_a1 = 1;
		} else if (!have_len) {
			if (zexpr_eval(opt, &d->regs, &len) < 0 || len == 0) {
				printf("bad length\n");
				return -1;
			}
			have_len = 1;
		} else if (!have_a2) {
			if (eval_addr(d, opt, &a2) < 0) {
				printf("bad address\n");
				return -1;
			}
			have_a2 = 1;
		} else {
			printf("usage: c [-limit N] addr1 len addr2\n");
			return -1;
		}
	}
	if (!have_a1 || !have_len || !have_a2) {
		printf("usage: c [-limit N] addr1 len addr2\n");
		return -1;
	}
	if (!have_target(d)) {
		printf("no target\n");
		return -1;
	}

	off = 0;
	while (off < len) {
		uint64_t want64 = len - off;
		size_t want;
		size_t k;

		if (want64 > sizeof(b1))
			want = sizeof(b1);
		else
			want = (size_t)want64;
		if (ztarget_read(&d->target, a1 + off, b1, want) < 0) {
			printf("read failed at %016llx\n",
			    (unsigned long long)(a1 + off));
			return -1;
		}
		if (ztarget_read(&d->target, a2 + off, b2, want) < 0) {
			printf("read failed at %016llx\n",
			    (unsigned long long)(a2 + off));
			return -1;
		}
		for (k = 0; k < want; k++) {
			if (b1[k] == b2[k])
				continue;
			printf("%016llx: %02x != %02x   other=%016llx\n",
			    (unsigned long long)(a1 + off + k),
			    b1[k], b2[k],
			    (unsigned long long)(a2 + off + k));
			diffs++;
			if (diffs >= limit) {
				hit_limit = 1;
				break;
			}
		}
		if (hit_limit)
			break;
		off += want;
	}

	if (diffs == 0)
		printf("ranges equal\n");
	else if (hit_limit)
		printf("%d differences shown (limit reached)\n", diffs);
	else
		printf("%d differences shown\n", diffs);
	return 0;
}

/* --- m src len dst -------------------------------------------- */
static int
cmd_m(struct zdbg *d, struct toks *t)
{
	zaddr_t src, dst;
	uint64_t len;
	uint8_t buf[ZDBG_MEMIO_CHUNK];
	uint64_t off;
	int backward;
	size_t total_written = 0;
	int rc;

	if (t->n != 4) {
		printf("usage: m src len dst\n");
		return -1;
	}
	if (eval_addr(d, t->v[1], &src) < 0) {
		printf("bad source address\n");
		return -1;
	}
	if (zexpr_eval(t->v[2], &d->regs, &len) < 0 || len == 0) {
		printf("bad length\n");
		return -1;
	}
	if (eval_addr(d, t->v[3], &dst) < 0) {
		printf("bad destination address\n");
		return -1;
	}
	if (!have_target(d)) {
		printf("no target\n");
		return -1;
	}
	if (!target_stopped(d)) {
		printf("no stopped target\n");
		return -1;
	}

	/* memmove-safe overlap: copy backward when dst is inside
	 * (src, src+len) so a chunked forward copy would clobber
	 * source bytes before we read them. */
	backward = (dst > src) && (dst < src + len);

	off = 0;
	while (off < len) {
		uint64_t remaining = len - off;
		size_t want = sizeof(buf);
		uint64_t cur;
		size_t written = 0;

		if ((uint64_t)want > remaining)
			want = (size_t)remaining;
		cur = backward ? (len - off - want) : off;

		if (ztarget_read(&d->target, src + cur, buf, want) < 0) {
			printf("move failed after %llu bytes written\n",
			    (unsigned long long)total_written);
			return -1;
		}
		rc = zdbg_patch_write_chunked(d, dst + cur, buf, want, "m",
		    &written);
		total_written += written;
		if (rc < 0) {
			printf("move failed after %llu bytes written\n",
			    (unsigned long long)total_written);
			return -1;
		}
		if (rc > 0) {
			printf("patch journal full after %llu bytes written\n",
			    (unsigned long long)total_written);
			return -1;
		}
		off += want;
	}
	printf("moved %llu bytes from %016llx to %016llx\n",
	    (unsigned long long)len,
	    (unsigned long long)src, (unsigned long long)dst);
	return 0;
}

/* --- wf addr len path ----------------------------------------- */
static int
cmd_wf(struct zdbg *d, struct toks *t)
{
	struct cmd_qargs a;
	const char *cmd_line;
	zaddr_t addr;
	uint64_t len;
	const char *path;
	FILE *fp;
	uint8_t buf[ZDBG_MEMIO_CHUNK];
	uint64_t off;
	uint64_t total = 0;

	cmd_line = rest_from(t->orig, 1);
	if (cmd_qsplit(cmd_line, &a) < 0) {
		printf("argument list too long\n");
		return -1;
	}
	if (a.n != 3) {
		printf("usage: wf addr len path\n");
		return -1;
	}
	if (eval_addr(d, a.v[0], &addr) < 0) {
		printf("bad address\n");
		return -1;
	}
	if (zexpr_eval(a.v[1], &d->regs, &len) < 0 || len == 0) {
		printf("bad length\n");
		return -1;
	}
	path = a.v[2];
	if (!have_target(d)) {
		printf("no target\n");
		return -1;
	}

	fp = fopen(path, "wb");
	if (fp == NULL) {
		printf("could not open file: %s\n", path);
		return -1;
	}

	off = 0;
	while (off < len) {
		uint64_t remaining = len - off;
		size_t want = sizeof(buf);
		size_t got;

		if ((uint64_t)want > remaining)
			want = (size_t)remaining;
		if (ztarget_read(&d->target, addr + off, buf, want) < 0) {
			printf("read failed at %016llx after %llu bytes\n",
			    (unsigned long long)(addr + off),
			    (unsigned long long)total);
			fclose(fp);
			return -1;
		}
		got = fwrite(buf, 1, want, fp);
		if (got != want) {
			printf("write to %s failed after %llu bytes\n",
			    path, (unsigned long long)(total + got));
			fclose(fp);
			return -1;
		}
		total += want;
		off += want;
	}
	if (fclose(fp) != 0) {
		printf("close %s failed after %llu bytes\n",
		    path, (unsigned long long)total);
		return -1;
	}
	printf("wrote %llu bytes to %s\n",
	    (unsigned long long)total, path);
	return 0;
}

/* --- rf path addr [len] --------------------------------------- */
static int
cmd_rf(struct zdbg *d, struct toks *t)
{
	struct cmd_qargs a;
	const char *cmd_line;
	const char *path;
	zaddr_t addr;
	uint64_t len = 0;
	int have_explicit_len = 0;
	FILE *fp;
	uint8_t buf[ZDBG_MEMIO_CHUNK];
	uint64_t total = 0;
	int eof_short = 0;

	cmd_line = rest_from(t->orig, 1);
	if (cmd_qsplit(cmd_line, &a) < 0) {
		printf("argument list too long\n");
		return -1;
	}
	if (a.n != 2 && a.n != 3) {
		printf("usage: rf path addr [len]\n");
		return -1;
	}
	path = a.v[0];
	if (eval_addr(d, a.v[1], &addr) < 0) {
		printf("bad address\n");
		return -1;
	}
	if (a.n == 3) {
		if (zexpr_eval(a.v[2], &d->regs, &len) < 0 || len == 0) {
			printf("bad length\n");
			return -1;
		}
		have_explicit_len = 1;
	}
	if (!have_target(d)) {
		printf("no target\n");
		return -1;
	}
	if (!target_stopped(d)) {
		printf("no stopped target\n");
		return -1;
	}

	fp = fopen(path, "rb");
	if (fp == NULL) {
		printf("could not open file: %s\n", path);
		return -1;
	}

	for (;;) {
		size_t want = sizeof(buf);
		size_t got;
		size_t written = 0;
		int rc;

		if (have_explicit_len) {
			uint64_t remaining = len - total;
			if (remaining == 0)
				break;
			if ((uint64_t)want > remaining)
				want = (size_t)remaining;
		}
		got = fread(buf, 1, want, fp);
		if (got == 0) {
			if (have_explicit_len && total < len)
				eof_short = 1;
			break;
		}
		rc = zdbg_patch_write_chunked(d, addr + total, buf, got,
		    "rf", &written);
		total += written;
		if (rc < 0) {
			printf("write to target failed after %llu bytes\n",
			    (unsigned long long)total);
			fclose(fp);
			return -1;
		}
		if (rc > 0) {
			printf("patch journal full after %llu bytes written\n",
			    (unsigned long long)total);
			fclose(fp);
			return -1;
		}
		if (got < want) {
			/* short read: file is shorter than requested */
			if (have_explicit_len && total < len)
				eof_short = 1;
			break;
		}
	}
	fclose(fp);

	if (eof_short)
		printf("wrote %llu bytes from %s to %016llx "
		    "(EOF before requested %llu bytes)\n",
		    (unsigned long long)total, path,
		    (unsigned long long)addr,
		    (unsigned long long)len);
	else
		printf("wrote %llu bytes from %s to %016llx\n",
		    (unsigned long long)total, path,
		    (unsigned long long)addr);
	return 0;
}

/* --- u --------------------------------------------------------- */

/*
 * Print a decoded instruction with the same layout as
 * ztinydis_print() and, when the instruction has a direct
 * target and symbols are loaded, append ` <symbol+off>`.  The
 * core tinydis decoder stays symbol-free; symbolisation is
 * applied only at print time.
 */
static void
print_disasm_line(struct zdbg *d, const struct ztinydis *dis)
{
	char hex[64];
	char ann[ZDBG_SYM_NAME_MAX + ZDBG_SYM_MODULE_MAX + 48];
	size_t pos = 0;
	size_t i;

	if (dis == NULL)
		return;
	hex[0] = 0;
	for (i = 0; i < dis->len && pos + 3 < sizeof(hex); i++) {
		pos += (size_t)snprintf(hex + pos, sizeof(hex) - pos,
		    "%02x ", dis->bytes[i]);
	}
	ann[0] = 0;
	if (dis->has_target)
		annot_addr(d, dis->target, ann, sizeof(ann));
	printf("%016llx  %-20s  %s%s\n",
	    (unsigned long long)dis->addr, hex, dis->text, ann);
}

static int
cmd_u(struct zdbg *d, struct toks *t)
{
	zaddr_t addr = d->asm_addr;
	int count = 8;
	uint8_t buf[128];
	int i;

	if (t->n >= 2) {
		if (eval_addr(d, t->v[1], &addr) < 0) {
			printf("bad address\n");
			return -1;
		}
	}
	if (t->n >= 3) {
		uint64_t v;
		if (zexpr_eval(t->v[2], &d->regs, &v) < 0 || v == 0) {
			printf("bad count\n");
			return -1;
		}
		count = (int)v;
	}
	if (!have_target(d) ||
	    ztarget_read(&d->target, addr, buf, sizeof(buf)) < 0) {
		printf("target operation not available in this backend yet\n");
		return -1;
	}
	{
		size_t off = 0;
		for (i = 0; i < count; i++) {
			struct ztinydis dis;
			if (off >= sizeof(buf))
				break;
			if (ztinydis_one(addr, buf + off, sizeof(buf) - off,
			    &dis) < 0)
				break;
			print_disasm_line(d, &dis);
			addr += dis.len;
			off += dis.len;
		}
	}
	d->asm_addr = addr;
	return 0;
}

/* --- a --------------------------------------------------------- */
static int
cmd_a(struct zdbg *d, struct toks *t)
{
	zaddr_t addr = d->asm_addr;
	char line[256];

	if (t->n >= 2) {
		if (eval_addr(d, t->v[1], &addr) < 0) {
			printf("bad address\n");
			return -1;
		}
	}
	printf("assemble at %016llx (empty line ends)\n",
	    (unsigned long long)addr);
	for (;;) {
		struct ztinyasm enc;
		size_t i;
		printf("%016llx- ", (unsigned long long)addr);
		if (fgets(line, sizeof(line), stdin) == NULL)
			break;
		/* strip newline */
		{
			size_t n = strlen(line);
			while (n > 0 &&
			    (line[n - 1] == '\n' || line[n - 1] == '\r'))
				line[--n] = 0;
		}
		if (line[0] == 0)
			break;
		if (ztinyasm_assemble(addr, line, &enc, &d->regs) < 0) {
			printf("bad instruction\n");
			continue;
		}
		printf("   ");
		for (i = 0; i < enc.len; i++)
			printf("%02x ", enc.code[i]);
		printf("\n");
		if (have_target(d)) {
			if (zdbg_patch_write(d, addr, enc.code, enc.len,
			    "a") < 0) {
				/* message already printed */
			}
		}
		addr += enc.len;
	}
	d->asm_addr = addr;
	return 0;
}

/* --- pa -------------------------------------------------------- */
static int
cmd_pa(struct zdbg *d, struct toks *t)
{
	zaddr_t addr;
	uint64_t len;
	uint8_t buf[ZDBG_TINYASM_MAX];
	size_t out_len = 0;

	if (t->n < 4) {
		printf("usage: pa addr len insn...\n");
		return -1;
	}
	if (eval_addr(d, t->v[1], &addr) < 0) {
		printf("bad address\n");
		return -1;
	}
	if (zexpr_eval(t->v[2], &d->regs, &len) < 0 || len == 0 ||
	    len > sizeof(buf)) {
		printf("bad length\n");
		return -1;
	}
	if (ztinyasm_patch(addr, (size_t)len, rest_from(t->orig, 3), buf,
	    sizeof(buf), &out_len, &d->regs) < 0) {
		printf("assemble failed\n");
		return -1;
	}
	{
		size_t i;
		printf("patch %016llx:", (unsigned long long)addr);
		for (i = 0; i < out_len; i++)
			printf(" %02x", buf[i]);
		printf("\n");
	}
	if (have_target(d))
		return zdbg_patch_write(d, addr, buf, out_len, "pa");
	return 0;
}

/* --- ij -------------------------------------------------------- */
static int
cmd_ij(struct zdbg *d, struct toks *t)
{
	zaddr_t addr;
	uint8_t buf[8];
	size_t used = 0;

	if (t->n < 2) {
		printf("usage: ij addr\n");
		return -1;
	}
	if (eval_addr(d, t->v[1], &addr) < 0) {
		printf("bad address\n");
		return -1;
	}
	if (!have_target(d) ||
	    ztarget_read(&d->target, addr, buf, sizeof(buf)) < 0) {
		printf("target operation not available in this backend yet\n");
		return -1;
	}
	if (zpatch_invert_jcc(buf, sizeof(buf), &used) < 0) {
		printf("no jz/jnz at %016llx\n", (unsigned long long)addr);
		return -1;
	}
	return zdbg_patch_write(d, addr, buf, used, "ij");
}

/* --- b / bc / bd / be ------------------------------------------ */
static int
cmd_b(struct zdbg *d, struct toks *t)
{
	zaddr_t addr;
	int id;

	if (t->n == 1) {
		zbp_list(&d->bps);
		return 0;
	}
	if (eval_addr(d, t->v[1], &addr) < 0) {
		printf("bad address\n");
		return -1;
	}
	id = zbp_alloc(&d->bps, addr, 0);
	if (id < 0) {
		printf("breakpoint table full\n");
		return -1;
	}
	if (have_target(d))
		(void)zbp_enable(&d->target, &d->bps, id);
	else
		d->bps.bp[id].state = ZBP_ENABLED;
	printf("bp %d at %016llx %s %s\n", id, (unsigned long long)addr,
	    d->bps.bp[id].state == ZBP_ENABLED ? "enabled" : "disabled",
	    d->bps.bp[id].installed ? "installed" : "removed");
	return 0;
}

static int
parse_bp_id(const char *s, int *idp)
{
	uint64_t v;
	if (zexpr_eval(s, NULL, &v) < 0)
		return -1;
	if (v >= ZDBG_MAX_BREAKPOINTS)
		return -1;
	*idp = (int)v;
	return 0;
}

static int
cmd_bc(struct zdbg *d, struct toks *t)
{
	int id;
	if (t->n < 2) {
		printf("usage: bc n|*\n");
		return -1;
	}
	if (strcmp(t->v[1], "*") == 0) {
		for (id = 0; id < ZDBG_MAX_BREAKPOINTS; id++)
			(void)zbp_clear(&d->target, &d->bps, id);
		d->stopped_bp = -1;
		return 0;
	}
	if (parse_bp_id(t->v[1], &id) < 0) {
		printf("bad id\n");
		return -1;
	}
	if (zbp_clear(&d->target, &d->bps, id) < 0)
		return -1;
	if (d->stopped_bp == id)
		d->stopped_bp = -1;
	return 0;
}

static int
cmd_bd(struct zdbg *d, struct toks *t)
{
	int id;
	if (t->n < 2 || parse_bp_id(t->v[1], &id) < 0) {
		printf("usage: bd n\n");
		return -1;
	}
	if (zbp_disable(&d->target, &d->bps, id) < 0) {
		printf("target operation not available in this backend yet\n");
		return -1;
	}
	if (d->stopped_bp == id)
		d->stopped_bp = -1;
	return 0;
}

static int
cmd_be(struct zdbg *d, struct toks *t)
{
	int id;
	struct zbp *b;
	if (t->n < 2 || parse_bp_id(t->v[1], &id) < 0) {
		printf("usage: be n\n");
		return -1;
	}
	b = &d->bps.bp[id];
	if (b->state == ZBP_EMPTY) {
		printf("no breakpoint %d\n", id);
		return -1;
	}
	/*
	 * If we are currently stopped exactly at this breakpoint's
	 * address waiting to execute the original instruction, do
	 * not reinstall 0xcc here: the resume-from-bp path will do
	 * that after the internal single-step.  Leave it logically
	 * enabled and uninstalled.
	 */
	if (d->stopped_bp == id) {
		b->state = ZBP_ENABLED;
		return 0;
	}
	if (zbp_enable(&d->target, &d->bps, id) < 0) {
		printf("target operation not available in this backend yet\n");
		return -1;
	}
	return 0;
}

/* --- hb / hw / hl / hc / hd / he ------------------------------- */

static int
parse_hwbp_id(const char *s, int *idp)
{
	uint64_t v;
	if (zexpr_eval(s, NULL, &v) < 0)
		return -1;
	if (v >= ZDBG_MAX_HWBP)
		return -1;
	*idp = (int)v;
	return 0;
}

static void
print_hwbp_summary(struct zdbg *d, int id)
{
	const struct zhwbp *b;
	char ann[ZDBG_SYM_NAME_MAX + ZDBG_SYM_MODULE_MAX + 48];
	const char *kname;

	if (id < 0 || id >= ZDBG_MAX_HWBP)
		return;
	b = &d->hwbps.bp[id];
	annot_addr(d, b->addr, ann, sizeof(ann));
	kname = (b->kind == ZHWBP_EXEC) ? "exec" :
	    (b->kind == ZHWBP_WRITE) ? "write" : "readwrite";
	printf("hw %d %s len=%d at %016llx%s\n", id, kname, b->len,
	    (unsigned long long)b->addr, ann);
}

static int
cmd_hb(struct zdbg *d, struct toks *t)
{
	zaddr_t addr;
	int id;

	if (t->n < 2) {
		printf("usage: hb addr\n");
		return -1;
	}
	if (eval_addr(d, t->v[1], &addr) < 0) {
		printf("bad address\n");
		return -1;
	}
	id = zhwbp_alloc(&d->hwbps, addr, ZHWBP_EXEC, 1);
	if (id < 0) {
		printf("hardware slots exhausted\n");
		return -1;
	}
	if (have_target(d) && target_stopped(d)) {
		if (zhwbp_enable(&d->target, &d->hwbps, id) < 0) {
			printf("hardware breakpoint enable failed\n");
			(void)zhwbp_clear(&d->target, &d->hwbps, id);
			return -1;
		}
	} else {
		d->hwbps.bp[id].state = ZHWBP_ENABLED;
	}
	print_hwbp_summary(d, id);
	return 0;
}

static int
parse_hw_kind(const char *s, enum zhwbp_kind *kp)
{
	if (strcmp(s, "w") == 0) {
		*kp = ZHWBP_WRITE;
		return 0;
	}
	if (strcmp(s, "rw") == 0) {
		*kp = ZHWBP_READWRITE;
		return 0;
	}
	return -1;
}

static int
cmd_hw(struct zdbg *d, struct toks *t)
{
	zaddr_t addr;
	uint64_t len;
	enum zhwbp_kind kind;
	int id;

	if (t->n < 4) {
		printf("usage: hw addr len w|rw\n");
		return -1;
	}
	if (eval_addr(d, t->v[1], &addr) < 0) {
		printf("bad address\n");
		return -1;
	}
	if (zexpr_eval(t->v[2], &d->regs, &len) < 0) {
		printf("bad length\n");
		return -1;
	}
	/* r is rejected explicitly: x86 has no read-only watchpoint. */
	if (strcmp(t->v[3], "r") == 0) {
		printf("x86 has no read-only data watchpoint; use rw\n");
		return -1;
	}
	if (parse_hw_kind(t->v[3], &kind) < 0) {
		printf("bad type; use w or rw\n");
		return -1;
	}
	if (len != 1 && len != 2 && len != 4 && len != 8) {
		printf("bad length; must be 1, 2, 4, or 8\n");
		return -1;
	}
	if ((addr % (zaddr_t)len) != 0) {
		printf("unaligned address for len=%llu\n",
		    (unsigned long long)len);
		return -1;
	}
	id = zhwbp_alloc(&d->hwbps, addr, kind, (int)len);
	if (id < 0) {
		printf("hardware slots exhausted\n");
		return -1;
	}
	if (have_target(d) && target_stopped(d)) {
		if (zhwbp_enable(&d->target, &d->hwbps, id) < 0) {
			printf("watchpoint enable failed\n");
			(void)zhwbp_clear(&d->target, &d->hwbps, id);
			return -1;
		}
	} else {
		d->hwbps.bp[id].state = ZHWBP_ENABLED;
	}
	print_hwbp_summary(d, id);
	return 0;
}

static int
cmd_hl(struct zdbg *d, struct toks *t)
{
	int i;
	int any = 0;

	(void)t;
	for (i = 0; i < ZDBG_MAX_HWBP; i++) {
		const struct zhwbp *b = &d->hwbps.bp[i];
		char ann[ZDBG_SYM_NAME_MAX + ZDBG_SYM_MODULE_MAX + 48];
		char cond[ZDBG_FILTER_EXPR_MAX + 8];
		const char *s;
		const char *kname;

		if (b->state == ZHWBP_EMPTY)
			continue;
		s = (b->state == ZHWBP_ENABLED) ? "enabled " : "disabled";
		kname = (b->kind == ZHWBP_EXEC) ? "exec     " :
		    (b->kind == ZHWBP_WRITE) ? "write    " : "readwrite";
		annot_addr(d, b->addr, ann, sizeof(ann));
		if (b->filter.has_cond)
			snprintf(cond, sizeof(cond), "cond=\"%s\"",
			    b->filter.cond);
		else
			snprintf(cond, sizeof(cond), "cond=none");
		{
			char act[32];
			if (b->actions.silent)
				snprintf(act, sizeof(act),
				    "actions=%d silent", b->actions.count);
			else
				snprintf(act, sizeof(act), "actions=%d",
				    b->actions.count);
			printf(" %d %s %s len=%d hits=%llu ignore=%llu %s %s"
			    " %016llx%s\n",
			    i, s, kname, b->len,
			    (unsigned long long)b->filter.hits,
			    (unsigned long long)b->filter.ignore,
			    cond, act,
			    (unsigned long long)b->addr, ann);
		}
		any = 1;
	}
	if (!any)
		printf(" no hardware breakpoints\n");
	return 0;
}

static int
cmd_hc(struct zdbg *d, struct toks *t)
{
	int id;

	if (t->n < 2) {
		printf("usage: hc n|*\n");
		return -1;
	}
	if (strcmp(t->v[1], "*") == 0) {
		(void)zhwbp_clear_all(&d->target, &d->hwbps);
		d->stopped_hwbp = -1;
		return 0;
	}
	if (parse_hwbp_id(t->v[1], &id) < 0) {
		printf("bad id\n");
		return -1;
	}
	if (zhwbp_clear(&d->target, &d->hwbps, id) < 0)
		return -1;
	if (d->stopped_hwbp == id)
		d->stopped_hwbp = -1;
	return 0;
}

static int
cmd_hd(struct zdbg *d, struct toks *t)
{
	int id;

	if (t->n < 2 || parse_hwbp_id(t->v[1], &id) < 0) {
		printf("usage: hd n\n");
		return -1;
	}
	if (zhwbp_disable(&d->target, &d->hwbps, id) < 0) {
		printf("disable failed\n");
		return -1;
	}
	if (d->stopped_hwbp == id)
		d->stopped_hwbp = -1;
	return 0;
}

static int
cmd_he(struct zdbg *d, struct toks *t)
{
	int id;

	if (t->n < 2 || parse_hwbp_id(t->v[1], &id) < 0) {
		printf("usage: he n\n");
		return -1;
	}
	if (d->hwbps.bp[id].state == ZHWBP_EMPTY) {
		printf("no hardware breakpoint %d\n", id);
		return -1;
	}
	if (zhwbp_enable(&d->target, &d->hwbps, id) < 0) {
		printf("enable failed\n");
		return -1;
	}
	return 0;
}

/* --- cond / ignore / hits -------------------------------------- */

/*
 * Look up a "b" or "h" subject and resolve the breakpoint id.
 * On success returns 0 and stores the filter pointer plus a
 * label ("bp" / "hwbp") for diagnostics.  Returns -1 on a bad
 * subject token, bad id, or empty slot.
 */
static int
filter_resolve(struct zdbg *d, const char *which, const char *idtok,
    struct zstop_filter **fp, const char **labelp, int *idp)
{
	uint64_t v;

	if (which == NULL || idtok == NULL || fp == NULL ||
	    labelp == NULL || idp == NULL)
		return -1;
	if (strcmp(which, "b") == 0) {
		if (zexpr_eval(idtok, NULL, &v) < 0)
			return -1;
		if (v >= ZDBG_MAX_BREAKPOINTS)
			return -1;
		if (d->bps.bp[v].state == ZBP_EMPTY)
			return -1;
		*fp = &d->bps.bp[v].filter;
		*labelp = "bp";
		*idp = (int)v;
		return 0;
	}
	if (strcmp(which, "h") == 0) {
		if (zexpr_eval(idtok, NULL, &v) < 0)
			return -1;
		if (v >= ZDBG_MAX_HWBP)
			return -1;
		if (d->hwbps.bp[v].state == ZHWBP_EMPTY)
			return -1;
		*fp = &d->hwbps.bp[v].filter;
		*labelp = "hwbp";
		*idp = (int)v;
		return 0;
	}
	return -1;
}

/*
 * cond b|h ID [EXPR... | clear]
 *
 * With no EXPR the current condition is shown.  With "clear"
 * the condition is removed.  Otherwise the rest of the line
 * starting at argv[3] is taken verbatim as the condition text;
 * this preserves whitespace inside expressions like
 *   cond b 0 rdi == #3
 */
static int
cmd_cond(struct zdbg *d, struct toks *t)
{
	struct zstop_filter *f = NULL;
	const char *label = "?";
	int id = -1;
	const char *expr;

	if (t->n < 3) {
		printf("usage: cond b|h ID [EXPR... | clear]\n");
		return -1;
	}
	if (filter_resolve(d, t->v[1], t->v[2], &f, &label, &id) < 0) {
		printf("cond: bad subject or id\n");
		return -1;
	}
	if (t->n == 3) {
		if (f->has_cond)
			printf("%s %d condition: %s\n", label, id, f->cond);
		else
			printf("%s %d condition: none\n", label, id);
		return 0;
	}
	if (t->n == 4 && strcmp(t->v[3], "clear") == 0) {
		zfilter_clear_condition(f);
		printf("%s %d condition cleared\n", label, id);
		return 0;
	}
	expr = rest_from(t->orig, 3);
	while (*expr == ' ' || *expr == '\t')
		expr++;
	if (*expr == 0) {
		printf("usage: cond b|h ID EXPR... | clear\n");
		return -1;
	}
	if (zfilter_set_condition(f, expr) < 0) {
		printf("cond: condition too long (max %d)\n",
		    ZDBG_FILTER_EXPR_MAX - 1);
		return -1;
	}
	printf("%s %d condition: %s\n", label, id, f->cond);
	return 0;
}

/* ignore b|h ID COUNT  -- replaces the current ignore count. */
static int
cmd_ignore(struct zdbg *d, struct toks *t)
{
	struct zstop_filter *f = NULL;
	const char *label = "?";
	int id = -1;
	uint64_t n;

	if (t->n < 4) {
		printf("usage: ignore b|h ID COUNT\n");
		return -1;
	}
	if (filter_resolve(d, t->v[1], t->v[2], &f, &label, &id) < 0) {
		printf("ignore: bad subject or id\n");
		return -1;
	}
	if (zexpr_eval(t->v[3], NULL, &n) < 0) {
		printf("ignore: bad count\n");
		return -1;
	}
	zfilter_set_ignore(f, n);
	printf("%s %d will ignore next %llu hits\n", label, id,
	    (unsigned long long)n);
	return 0;
}

/*
 * hits b|h ID [reset]
 * hits b|h *  reset    (reset every breakpoint of that kind)
 */
static int
cmd_hits(struct zdbg *d, struct toks *t)
{
	struct zstop_filter *f = NULL;
	const char *label = "?";
	int id = -1;
	int reset = 0;

	if (t->n < 3) {
		printf("usage: hits b|h ID [reset]\n");
		return -1;
	}
	reset = (t->n >= 4 && strcmp(t->v[3], "reset") == 0);

	if (strcmp(t->v[2], "*") == 0) {
		int i;
		int max;
		if (!reset) {
			printf("usage: hits b|h * reset\n");
			return -1;
		}
		if (strcmp(t->v[1], "b") == 0) {
			max = ZDBG_MAX_BREAKPOINTS;
			for (i = 0; i < max; i++) {
				if (d->bps.bp[i].state != ZBP_EMPTY)
					zfilter_reset_hits(
					    &d->bps.bp[i].filter);
			}
			printf("bp * hits reset\n");
			return 0;
		}
		if (strcmp(t->v[1], "h") == 0) {
			max = ZDBG_MAX_HWBP;
			for (i = 0; i < max; i++) {
				if (d->hwbps.bp[i].state != ZHWBP_EMPTY)
					zfilter_reset_hits(
					    &d->hwbps.bp[i].filter);
			}
			printf("hwbp * hits reset\n");
			return 0;
		}
		printf("hits: bad subject\n");
		return -1;
	}

	if (filter_resolve(d, t->v[1], t->v[2], &f, &label, &id) < 0) {
		printf("hits: bad subject or id\n");
		return -1;
	}
	if (reset) {
		zfilter_reset_hits(f);
		printf("%s %d hits reset\n", label, id);
		return 0;
	}
	if (f->has_cond)
		printf("%s %d hits=%llu ignore=%llu condition=\"%s\"\n",
		    label, id,
		    (unsigned long long)f->hits,
		    (unsigned long long)f->ignore,
		    f->cond);
	else
		printf("%s %d hits=%llu ignore=%llu condition=none\n",
		    label, id,
		    (unsigned long long)f->hits,
		    (unsigned long long)f->ignore);
	return 0;
}

/* --- actions / printf / trace --------------------------------- */

/*
 * Look up a "b" or "h" subject and resolve the breakpoint id,
 * returning a pointer to its action list.  Returns 0 on success
 * and -1 on a bad subject token, bad id, or empty slot.
 */
static int
actions_resolve(struct zdbg *d, const char *which, const char *idtok,
    struct zaction_list **ap, const char **labelp, int *idp)
{
	uint64_t v;

	if (which == NULL || idtok == NULL || ap == NULL ||
	    labelp == NULL || idp == NULL)
		return -1;
	if (strcmp(which, "b") == 0) {
		if (zexpr_eval(idtok, NULL, &v) < 0)
			return -1;
		if (v >= ZDBG_MAX_BREAKPOINTS)
			return -1;
		if (d->bps.bp[v].state == ZBP_EMPTY)
			return -1;
		*ap = &d->bps.bp[v].actions;
		*labelp = "bp";
		*idp = (int)v;
		return 0;
	}
	if (strcmp(which, "h") == 0) {
		if (zexpr_eval(idtok, NULL, &v) < 0)
			return -1;
		if (v >= ZDBG_MAX_HWBP)
			return -1;
		if (d->hwbps.bp[v].state == ZHWBP_EMPTY)
			return -1;
		*ap = &d->hwbps.bp[v].actions;
		*labelp = "hwbp";
		*idp = (int)v;
		return 0;
	}
	return -1;
}

static void
actions_print(const char *label, int id, const struct zaction_list *a)
{
	int i;

	printf("%s %d actions: silent=%s count=%d\n", label, id,
	    a->silent ? "yes" : "no", a->count);
	for (i = 0; i < a->count; i++)
		printf("  %d %s\n", i, a->lines[i]);
}

/*
 * actions b|h ID                 show action list
 * actions b|h ID add LINE...     append action line
 * actions b|h ID del INDEX       delete action line
 * actions b|h ID set INDEX LINE  replace action line
 * actions b|h ID clear           clear actions and silent flag
 * actions b|h ID silent on|off   set silent flag
 */
static int
cmd_actions(struct zdbg *d, struct toks *t)
{
	struct zaction_list *a = NULL;
	const char *label = "?";
	int id = -1;
	const char *sub;
	const char *line;

	if (t->n < 3) {
		printf("usage: actions b|h ID [add LINE|del N|set N LINE|"
		    "clear|silent on|off]\n");
		return -1;
	}
	if (actions_resolve(d, t->v[1], t->v[2], &a, &label, &id) < 0) {
		printf("actions: bad subject or id\n");
		return -1;
	}
	if (t->n == 3) {
		actions_print(label, id, a);
		return 0;
	}
	sub = t->v[3];
	if (strcmp(sub, "clear") == 0) {
		zactions_clear(a);
		printf("%s %d actions cleared\n", label, id);
		return 0;
	}
	if (strcmp(sub, "silent") == 0) {
		if (t->n < 5) {
			printf("usage: actions b|h ID silent on|off\n");
			return -1;
		}
		if (strcmp(t->v[4], "on") == 0)
			zactions_set_silent(a, 1);
		else if (strcmp(t->v[4], "off") == 0)
			zactions_set_silent(a, 0);
		else {
			printf("usage: actions b|h ID silent on|off\n");
			return -1;
		}
		printf("%s %d silent=%s\n", label, id,
		    a->silent ? "yes" : "no");
		return 0;
	}
	if (strcmp(sub, "del") == 0) {
		uint64_t idx;
		if (t->n < 5 || zexpr_eval(t->v[4], NULL, &idx) < 0) {
			printf("usage: actions b|h ID del INDEX\n");
			return -1;
		}
		if (zactions_del(a, (int)idx) < 0) {
			printf("actions: bad index\n");
			return -1;
		}
		return 0;
	}
	if (strcmp(sub, "add") == 0) {
		line = rest_from(t->orig, 4);
		while (*line == ' ' || *line == '\t')
			line++;
		if (*line == 0) {
			printf("usage: actions b|h ID add LINE...\n");
			return -1;
		}
		/* Bare `silent` adds a flag rather than a line. */
		{
			const char *p = line;
			while (*p == ' ' || *p == '\t')
				p++;
			if ((p[0] == 's' || p[0] == 'S') &&
			    (p[1] == 'i' || p[1] == 'I') &&
			    (p[2] == 'l' || p[2] == 'L') &&
			    (p[3] == 'e' || p[3] == 'E') &&
			    (p[4] == 'n' || p[4] == 'N') &&
			    (p[5] == 't' || p[5] == 'T') &&
			    (p[6] == 0 || p[6] == ' ' || p[6] == '\t')) {
				zactions_set_silent(a, 1);
				return 0;
			}
		}
		if (!zactions_is_allowed(line)) {
			printf("action rejected: command not allowed in"
			    " breakpoint action list: %s\n", line);
			return -1;
		}
		if (zactions_add(a, line) < 0) {
			printf("actions: line too long or list full\n");
			return -1;
		}
		return 0;
	}
	if (strcmp(sub, "set") == 0) {
		uint64_t idx;
		if (t->n < 6 || zexpr_eval(t->v[4], NULL, &idx) < 0) {
			printf("usage: actions b|h ID set INDEX LINE...\n");
			return -1;
		}
		line = rest_from(t->orig, 5);
		while (*line == ' ' || *line == '\t')
			line++;
		if (*line == 0) {
			printf("usage: actions b|h ID set INDEX LINE...\n");
			return -1;
		}
		if (!zactions_is_allowed(line)) {
			printf("action rejected: command not allowed in"
			    " breakpoint action list: %s\n", line);
			return -1;
		}
		if (zactions_set(a, (int)idx, line) < 0) {
			printf("actions: bad index or line too long\n");
			return -1;
		}
		return 0;
	}
	printf("usage: actions b|h ID [add LINE|del N|set N LINE|"
	    "clear|silent on|off]\n");
	return -1;
}

/*
 * Decode a hex digit; returns -1 for non-hex.
 */
static int
hex_digit(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return 10 + (c - 'a');
	if (c >= 'A' && c <= 'F')
		return 10 + (c - 'A');
	return -1;
}

/*
 * printf TEXT...
 *
 * Print the rest of the line followed by a newline.  Recognises
 * a small set of C-style backslash escapes: \n \t \r \\ \" and
 * \xNN.  No format substitutions: the text is literal.
 */
static int
cmd_printf(struct zdbg *d, struct toks *t)
{
	const char *p;
	int hi;
	int lo;

	(void)d;
	p = rest_from(t->orig, 1);
	/* Do not skip the leading whitespace: `printf <space>foo`
	 * preserves the explicit space.  However a single token
	 * after the keyword would yield t->n >= 2 and rest_from
	 * already starts at that token.  When the user typed only
	 * `printf` with no args, just emit a newline. */
	for (; *p; p++) {
		if (*p != '\\') {
			fputc((unsigned char)*p, stdout);
			continue;
		}
		switch (p[1]) {
		case 'n': fputc('\n', stdout); p++; break;
		case 't': fputc('\t', stdout); p++; break;
		case 'r': fputc('\r', stdout); p++; break;
		case '\\': fputc('\\', stdout); p++; break;
		case '"': fputc('"', stdout); p++; break;
		case 'x':
			hi = hex_digit((unsigned char)p[2]);
			lo = hex_digit((unsigned char)p[3]);
			if (hi < 0 || lo < 0) {
				/* malformed: emit literally */
				fputc('\\', stdout);
				continue;
			}
			fputc((hi << 4) | lo, stdout);
			p += 3;
			break;
		case 0:
			fputc('\\', stdout);
			break;
		default:
			fputc('\\', stdout);
			fputc((unsigned char)p[1], stdout);
			p++;
			break;
		}
	}
	fputc('\n', stdout);
	return 0;
}

/*
 * trace b ADDR [TEXT...]   create a software tracepoint
 * trace h ID   [TEXT...]   make an existing hwbp into a tracepoint
 *
 * A tracepoint is just a breakpoint/watchpoint with silent=on
 * and a default action list of `printf <message>` followed by
 * `continue`.  Existing actions on the slot are replaced.
 */
static int
cmd_trace(struct zdbg *d, struct toks *t)
{
	struct zaction_list *a;
	zaddr_t addr;
	int id;
	const char *msg;
	const char *sub;
	char line[ZDBG_ACTION_LINE_MAX];

	if (t->n < 3) {
		printf("usage: trace b ADDR [TEXT...] | trace h ID"
		    " [TEXT...]\n");
		return -1;
	}
	sub = t->v[1];
	if (strcmp(sub, "b") == 0) {
		if (eval_addr(d, t->v[2], &addr) < 0) {
			printf("bad address\n");
			return -1;
		}
		id = zbp_alloc(&d->bps, addr, 0);
		if (id < 0) {
			printf("breakpoint table full\n");
			return -1;
		}
		if (have_target(d))
			(void)zbp_enable(&d->target, &d->bps, id);
		else
			d->bps.bp[id].state = ZBP_ENABLED;
		a = &d->bps.bp[id].actions;
		zactions_clear(a);
		zactions_set_silent(a, 1);
		msg = (t->n >= 4) ? rest_from(t->orig, 3) : NULL;
		if (msg != NULL)
			while (*msg == ' ' || *msg == '\t')
				msg++;
		if (msg != NULL && *msg)
			snprintf(line, sizeof(line), "printf %s", msg);
		else
			snprintf(line, sizeof(line),
			    "printf trace bp %d hit", id);
		if (zactions_add(a, line) < 0) {
			printf("trace: message too long\n");
			(void)zbp_clear(&d->target, &d->bps, id);
			return -1;
		}
		(void)zactions_add(a, "continue");
		printf("trace bp %d at %016llx\n", id,
		    (unsigned long long)addr);
		return 0;
	}
	if (strcmp(sub, "h") == 0) {
		uint64_t v;
		if (zexpr_eval(t->v[2], NULL, &v) < 0 ||
		    v >= ZDBG_MAX_HWBP) {
			printf("bad hwbp id\n");
			return -1;
		}
		id = (int)v;
		if (d->hwbps.bp[id].state == ZHWBP_EMPTY) {
			printf("no hardware breakpoint %d\n", id);
			return -1;
		}
		a = &d->hwbps.bp[id].actions;
		zactions_clear(a);
		zactions_set_silent(a, 1);
		msg = (t->n >= 4) ? rest_from(t->orig, 3) : NULL;
		if (msg != NULL)
			while (*msg == ' ' || *msg == '\t')
				msg++;
		if (msg != NULL && *msg)
			snprintf(line, sizeof(line), "printf %s", msg);
		else
			snprintf(line, sizeof(line),
			    "printf trace hwbp %d hit", id);
		if (zactions_add(a, line) < 0) {
			printf("trace: message too long\n");
			return -1;
		}
		(void)zactions_add(a, "continue");
		printf("trace hwbp %d\n", id);
		return 0;
	}
	printf("usage: trace b ADDR [TEXT...] | trace h ID [TEXT...]\n");
	return -1;
}

/*
 * Execute `a`'s action lines through zcmd_exec().  Sets
 * d->in_action across the run as a recursion guard.  Returns 0
 * on success, -1 on a failed action, and writes 1 into
 * *continuep when an explicit `continue`/`cont` action was seen
 * before any failure.
 *
 * `continue` is special: it is consumed here and never reaches
 * zcmd_exec.  Other lines are dispatched normally; the in_action
 * guard inside zcmd_exec keeps disallowed nested commands out.
 */
static int
zdbg_run_actions(struct zdbg *d, const struct zaction_list *a,
    int *continuep)
{
	int i;
	int rc;

	if (continuep != NULL)
		*continuep = 0;
	if (d == NULL || a == NULL || a->count == 0)
		return 0;
	if (d->in_action) {
		/* Defensive: should be impossible because zcmd_exec
		 * rejects nested action triggers, but if reached we
		 * must not loop. */
		printf("action rejected: nested action lists are not"
		    " supported\n");
		return -1;
	}
	d->in_action = 1;
	for (i = 0; i < a->count; i++) {
		const char *line = a->lines[i];
		if (zactions_is_continue(line)) {
			if (continuep != NULL)
				*continuep = 1;
			continue;
		}
		if (!zactions_is_allowed(line)) {
			printf("action rejected: command not allowed in"
			    " breakpoint action list: %s\n", line);
			d->in_action = 0;
			return -1;
		}
		rc = zcmd_exec(d, line);
		if (rc < 0) {
			printf("action failed: %s\n", line);
			d->in_action = 0;
			return -1;
		}
	}
	d->in_action = 0;
	return 0;
}

/* --- g / t ----------------------------------------------------- */

/*
 * Record the latest user-visible stop on d so the script-facing
 * `check stop`/`check exited`/`check rip` family can inspect it.
 * Called after a stop has been classified (breakpoint vs hwbp)
 * but before the auto-continue path filters non-stopping
 * signals/exceptions out, since auto-continued events do not
 * end up in front of the user.
 */
static void
record_last_stop(struct zdbg *d, const struct zstop *st)
{
	if (d == NULL || st == NULL)
		return;
	d->last_stop = *st;
	d->have_last_stop = 1;
	d->last_stop_hwbp = d->stopped_hwbp;
	d->last_stop_is_watch = 0;
	if (d->stopped_hwbp >= 0 && d->stopped_hwbp < ZDBG_MAX_HWBP) {
		const struct zhwbp *b = &d->hwbps.bp[d->stopped_hwbp];
		if (b->kind == ZHWBP_WRITE || b->kind == ZHWBP_READWRITE)
			d->last_stop_is_watch = 1;
	}
}

/*
 * Post-wait processing shared by g and t.  Refresh registers,
 * recognize x86-64 int3 breakpoint hits belonging to zdbg, and
 * apply the RIP-1 correction before the user sees the stop.
 *
 * After a known breakpoint hit the breakpoint is uninstalled
 * (original byte restored in target memory) and d->stopped_bp
 * holds the id.  The caller must arrange for reinstall before or
 * during the next resume.
 */
static void
zdbg_after_wait(struct zdbg *d, struct zstop *st, int *bp_idp)
{
	int id = -1;

	if (bp_idp != NULL)
		*bp_idp = -1;
	d->stopped_hwbp = -1;

	if (target_stopped(d))
		refresh_regs(d);

	if (st != NULL && st->reason == ZSTOP_BREAKPOINT &&
	    target_stopped(d) && d->have_regs) {
		int rc = zbp_handle_trap(&d->target, &d->bps, &d->regs, &id);
		if (rc == 1) {
			d->stopped_bp = id;
			st->addr = d->regs.rip;
			if (bp_idp != NULL)
				*bp_idp = id;
			/* keep cached regs consistent with target */
			refresh_regs(d);
			return;
		}
		/*
		 * Software handler did not claim this SIGTRAP.  Try
		 * the hardware DR6-based handler next.  On a hardware
		 * execute breakpoint RIP is already at the watched
		 * instruction, so we do not touch regs here.
		 */
		{
			int hw_id = -1;
			uint64_t dr6 = 0;
			int hrc = zhwbp_handle_trap(&d->target, &d->hwbps,
			    &hw_id, &dr6);
			if (hrc == 1) {
				d->stopped_hwbp = hw_id;
				if (d->have_regs)
					st->addr = d->regs.rip;
			}
		}
	} else if (st != NULL && st->reason == ZSTOP_SINGLESTEP &&
	    target_stopped(d) && d->have_regs) {
		/*
		 * On Windows (and in principle any x86 target)
		 * hardware breakpoints/watchpoints are delivered as
		 * EXCEPTION_SINGLE_STEP.  The backend cannot claim
		 * them because it does not know the generic hwbp
		 * table, so try DR6 here.  If no known slot matches
		 * we leave the stop as a normal single-step and user
		 * `t` behaves exactly as before.
		 */
		int hw_id = -1;
		uint64_t dr6 = 0;
		int hrc = zhwbp_handle_trap(&d->target, &d->hwbps,
		    &hw_id, &dr6);
		if (hrc == 1) {
			d->stopped_hwbp = hw_id;
			st->addr = d->regs.rip;
		}
	}
}

/*
 * If we are currently stopped on one of our own breakpoints,
 * step over the original instruction and reinstall the int3 so
 * the next resume does not re-hit the same trap immediately.
 *
 * Returns:
 *    0  caller should proceed with the user-requested resume
 *   +1  an internal single-step stop has already been reported;
 *       caller should not issue another resume/wait
 *   -1  error already printed
 */
static int
zdbg_resume_from_bp(struct zdbg *d, int user_singlestep)
{
	int id;
	struct zbp *b;
	struct zstop st;

	if (d->stopped_bp < 0)
		return 0;

	id = d->stopped_bp;
	d->stopped_bp = -1;
	if (id < 0 || id >= ZDBG_MAX_BREAKPOINTS)
		return 0;
	b = &d->bps.bp[id];

	/* breakpoint was cleared or disabled while stopped on it */
	if (b->state != ZBP_ENABLED)
		return 0;

	/* temporary breakpoint: do not reinstall; just drop it */
	if (b->temporary) {
		(void)zbp_clear(&d->target, &d->bps, id);
		return 0;
	}

	/* step the original instruction internally */
	if (ztarget_singlestep(&d->target) < 0) {
		printf("singlestep failed\n");
		return -1;
	}
	memset(&st, 0, sizeof(st));
	if (ztarget_wait(&d->target, &st) < 0) {
		printf("wait failed\n");
		return -1;
	}
	if (target_stopped(d))
		refresh_regs(d);

	/*
	 * If the internal step did not yield a clean single-step
	 * stop (target exited, got a signal, or hit another trap),
	 * report it to the user now and do not proceed with the
	 * user's resume.  Do not reinstall the int3 in that case.
	 */
	if (st.reason != ZSTOP_SINGLESTEP) {
		int bp_id = -1;
		zdbg_after_wait(d, &st, &bp_id);
		zstop_print(d, &st, bp_id);
		return 1;
	}

	/* reinstall the breakpoint now that we are past it */
	if (b->state == ZBP_ENABLED && !b->installed)
		(void)zbp_install(&d->target, &d->bps, id);

	if (user_singlestep) {
		/* user asked for t: report this single-step stop */
		zstop_print(d, &st, -1);
		return 1;
	}
	return 0;
}

/*
 * Run-until-stop helper shared by g and t.  After the ptrace
 * resume the command layer always waits and reports the stop,
 * so the REPL returns with the target either stopped or exited.
 *
 * On ZSTOP_SIGNAL the user's signal policy (struct zsig_table)
 * is consulted: the signal is printed when policy.print is set,
 * the pending signal is cleared when policy.pass is not set
 * (otherwise the backend will redeliver it on next continue),
 * and the loop auto-continues when policy.stop is not set so
 * noisy signals such as SIGCHLD/SIGWINCH never surface at the
 * prompt.  Breakpoint and single-step stops are unaffected.
 */
static int
cmd_run_and_wait(struct zdbg *d, int step)
{
	struct zstop st;
	int bp_id = -1;
	int rc;
	uint64_t auto_count = 0;

	if (!have_target(d)) {
		printf("no target\n");
		return -1;
	}

	if (d->stopped_bp >= 0) {
		rc = zdbg_resume_from_bp(d, step);
		if (rc < 0)
			return -1;
		if (rc == 1)
			return 0;
	}

	if (step) {
		if (ztarget_singlestep(&d->target) < 0) {
			printf("singlestep failed\n");
			return -1;
		}
	} else {
		/*
		 * Reprogram hardware debug registers across every
		 * currently-known traced thread before a full
		 * continue.  This catches up threads discovered
		 * via PTRACE_EVENT_CLONE during the previous run.
		 */
		(void)zhwbp_program(&d->target, &d->hwbps);
		if (ztarget_continue(&d->target) < 0) {
			printf("continue failed\n");
			return -1;
		}
	}

	for (;;) {
		memset(&st, 0, sizeof(st));
		if (ztarget_wait(&d->target, &st) < 0) {
			printf("wait failed\n");
			return -1;
		}
		zdbg_after_wait(d, &st, &bp_id);

		/*
		 * Breakpoint/watchpoint filter: hit count, ignore
		 * count, and optional condition.  Runs only for
		 * recognized zdbg-owned hits and only for non-temp
		 * software breakpoints.  When a hit is suppressed,
		 * auto-continue using the existing rearm dance for
		 * software breakpoints; hardware stops just continue.
		 */
		{
			struct zstop_filter *flt = NULL;
			struct zaction_list *acts = NULL;
			int sw_id = d->stopped_bp;
			int hw_id = d->stopped_hwbp;
			int is_sw = 0;
			int is_hw = 0;
			int cond_failed = 0;

			if (sw_id >= 0 && sw_id < ZDBG_MAX_BREAKPOINTS &&
			    !d->bps.bp[sw_id].temporary) {
				flt = &d->bps.bp[sw_id].filter;
				acts = &d->bps.bp[sw_id].actions;
				is_sw = 1;
			} else if (hw_id >= 0 && hw_id < ZDBG_MAX_HWBP) {
				flt = &d->hwbps.bp[hw_id].filter;
				acts = &d->hwbps.bp[hw_id].actions;
				is_hw = 1;
			}
			if (flt != NULL) {
				int should_stop = 1;
				flt->hits++;
				if (flt->ignore > 0) {
					flt->ignore--;
					should_stop = 0;
				} else if (flt->has_cond) {
					int cres = 0;
					const struct zmap_table *mt =
					    d->have_maps ? &d->maps : NULL;
					const struct zsym_table *syt =
					    d->have_syms ? &d->syms : NULL;
					if (zcond_eval(flt->cond, &d->regs,
					    mt, syt, &cres) < 0) {
						printf("condition evaluation"
						    " failed: %s\n",
						    flt->cond);
						should_stop = 1;
						cond_failed = 1;
					} else {
						should_stop = cres ? 1 : 0;
					}
				}
				if (!should_stop) {
					auto_count++;
					if (auto_count >
					    ZDBG_FILTER_AUTO_LIMIT) {
						printf("auto-continue limit"
						    " reached while"
						    " filtering"
						    " breakpoints\n");
						/* fall through to report */
					} else {
						if (is_sw) {
							int rrc;
							rrc = zdbg_resume_from_bp(
							    d, 0);
							if (rrc < 0)
								return -1;
							if (rrc == 1)
								return 0;
							(void)zhwbp_program(
							    &d->target,
							    &d->hwbps);
							if (ztarget_continue(
							    &d->target) < 0) {
								printf("continue"
								    " failed\n");
								return -1;
							}
						} else if (is_hw) {
							d->stopped_hwbp = -1;
							(void)zhwbp_program(
							    &d->target,
							    &d->hwbps);
							if (ztarget_continue(
							    &d->target) < 0) {
								printf("continue"
								    " failed\n");
								return -1;
							}
						}
						continue;
					}
				}
				/*
				 * Filter let the hit through.  If an
				 * action list is attached, print the
				 * normal stop output (unless silent),
				 * run the actions, and if the actions
				 * requested `continue`, resume via the
				 * same dance as a filtered-out hit.
				 *
				 * Skip actions when the condition
				 * failed to evaluate: the user needs
				 * to see the diagnostic and fix the
				 * expression first.
				 */
				if (acts != NULL && acts->count > 0 &&
				    !cond_failed) {
					int cont_after = 0;
					int arc;

					if (!acts->silent) {
						zstop_print(d, &st, bp_id);
						record_last_stop(d, &st);
					}
					arc = zdbg_run_actions(d, acts,
					    &cont_after);
					if (arc < 0) {
						/* Action failed: stop for
						 * the user.  Record the
						 * stop if silent had
						 * suppressed it earlier. */
						if (acts->silent)
							record_last_stop(d,
							    &st);
						return -1;
					}
					if (cont_after) {
						/* Tracepoint-style auto
						 * resume.  Silent + cont
						 * deliberately does not
						 * record last_stop. */
						if (is_sw) {
							int rrc;
							rrc = zdbg_resume_from_bp(
							    d, 0);
							if (rrc < 0)
								return -1;
							if (rrc == 1)
								return 0;
							(void)zhwbp_program(
							    &d->target,
							    &d->hwbps);
							if (ztarget_continue(
							    &d->target) < 0) {
								printf("continue"
								    " failed\n");
								return -1;
							}
						} else if (is_hw) {
							d->stopped_hwbp = -1;
							(void)zhwbp_program(
							    &d->target,
							    &d->hwbps);
							if (ztarget_continue(
							    &d->target) < 0) {
								printf("continue"
								    " failed\n");
								return -1;
							}
						}
						continue;
					}
					/* No continue action: stop at the
					 * prompt.  Record last_stop now
					 * if silent had skipped it. */
					if (acts->silent)
						record_last_stop(d, &st);
					return 0;
				}
			}
		}

		if (st.reason == ZSTOP_EXCEPTION) {
			const struct zexc_policy *xp;
			uint32_t xcode = (uint32_t)st.code;
			int do_stop = 1;
			int do_print = 1;
			int do_pass = 1;

			xp = zexc_get_policy(&d->excs, xcode);
			if (xp != NULL) {
				do_stop = xp->stop ? 1 : 0;
				do_print = xp->print ? 1 : 0;
				do_pass = xp->pass ? 1 : 0;
			}
			/*
			 * Apply pass/nopass to the pending Windows
			 * exception via the target API.  Linux
			 * returns -1 cleanly; that is not fatal.
			 */
			if (do_pass)
				(void)ztarget_set_pending_exception(
				    &d->target, st.tid, 0, -1, 1);
			else
				(void)ztarget_clear_pending_exception(
				    &d->target, st.tid);
			if (!do_stop) {
				if (do_print) {
					char tp[64];
					stop_thread_prefix(d, &st, tp,
					    sizeof(tp));
					printf("exception: %s%s(0x%08x) %s"
					    " %s\n", tp,
					    zexc_name(xcode),
					    (unsigned int)xcode,
					    st.first_chance ?
					    "first-chance" : "second-chance",
					    do_pass ? "passed" :
					    "suppressed");
				}
				/* auto-continue and keep waiting */
				(void)zhwbp_program(&d->target, &d->hwbps);
				if (ztarget_continue(&d->target) < 0) {
					printf("continue failed\n");
					return -1;
				}
				continue;
			}
			if (do_print)
				zstop_print(d, &st, bp_id);
			record_last_stop(d, &st);
			return 0;
		}

		if (st.reason == ZSTOP_SIGNAL) {
			const struct zsig_policy *p;
			int sig = st.code;
			int do_stop = 1;
			int do_print = 1;
			int do_pass = 1;

			p = zsig_get_policy(&d->sigs, sig);
			if (p != NULL) {
				do_stop = p->stop ? 1 : 0;
				do_print = p->print ? 1 : 0;
				do_pass = p->pass ? 1 : 0;
			}
			if (!do_pass)
				(void)ztarget_set_pending_signal(&d->target,
				    st.tid, 0);
			if (!do_stop) {
				if (do_print) {
					char tp[64];
					stop_thread_prefix(d, &st, tp,
					    sizeof(tp));
					printf("signal: %s%s(%d) passed\n",
					    tp, zsig_name(sig), sig);
				}
				/* auto-continue and keep waiting */
				(void)zhwbp_program(&d->target, &d->hwbps);
				if (ztarget_continue(&d->target) < 0) {
					printf("continue failed\n");
					return -1;
				}
				continue;
			}
			if (do_print) {
				zstop_print(d, &st, bp_id);
				if (do_pass && sig > 0)
					printf("pending: %s will be "
					    "delivered on continue\n",
					    zsig_name(sig));
			}
			record_last_stop(d, &st);
			return 0;
		}

		zstop_print(d, &st, bp_id);
		record_last_stop(d, &st);
		return 0;
	}
}

static int
cmd_g(struct zdbg *d, struct toks *t)
{
	(void)t;
	return cmd_run_and_wait(d, 0);
}

static int
cmd_t(struct zdbg *d, struct toks *t)
{
	(void)t;
	return cmd_run_and_wait(d, 1);
}

/* --- p --------------------------------------------------------- */

/*
 * Step over a single direct call rel32 using a temporary
 * breakpoint at the fallthrough address.  For non-call
 * instructions p degrades to a single step.
 *
 * This also handles the case where the user is currently stopped
 * on a permanent breakpoint placed exactly at the call: we skip
 * the normal resume-from-bp dance (which single-steps INTO the
 * call) and instead plant a temp bp at fallthrough, continue
 * without reinstalling the permanent int3, and reinstall the
 * permanent one after the temp fires.
 */
static int
cmd_p_once(struct zdbg *d)
{
	uint8_t ibuf[16];
	struct ztinydis dis;
	zaddr_t fallthrough;
	int temp_id = -1;
	int preexisting_id;
	int restore_perm_bp = -1;
	struct zstop st;
	int bp_id = -1;

	if (!have_target(d) || !target_stopped(d)) {
		printf("no target\n");
		return -1;
	}
	refresh_regs(d);
	if (!d->have_regs) {
		printf("no registers\n");
		return -1;
	}

	if (ztarget_read(&d->target, d->regs.rip, ibuf, sizeof(ibuf)) < 0) {
		printf("target operation not available in this backend yet\n");
		return -1;
	}
	if (ztinydis_one(d->regs.rip, ibuf, sizeof(ibuf), &dis) < 0 ||
	    dis.len == 0) {
		return cmd_run_and_wait(d, 1);
	}

	/* Only step over direct call rel32; everything else is plain
	 * single-step (which goes through the usual bp rearm path). */
	if (!(dis.kind == ZINSN_CALL && dis.is_call && dis.has_target)) {
		return cmd_run_and_wait(d, 1);
	}

	fallthrough = ztinydis_fallthrough(&dis);

	/* If a breakpoint already exists at fallthrough we can reuse
	 * it as-is (it is either installed and will fire, or disabled
	 * and we must install a temp - but zbp_alloc would reuse the
	 * slot so we keep the temp flag off).  Keep behavior simple:
	 * only install our own temp if the slot is free. */
	preexisting_id = zbp_find_by_addr(&d->bps, fallthrough);
	if (preexisting_id < 0) {
		temp_id = zbp_alloc(&d->bps, fallthrough, 1);
		if (temp_id < 0) {
			printf("breakpoint table full\n");
			return -1;
		}
		if (zbp_enable(&d->target, &d->bps, temp_id) < 0) {
			printf("temp breakpoint install failed\n");
			(void)zbp_clear(&d->target, &d->bps, temp_id);
			return -1;
		}
	} else if (d->bps.bp[preexisting_id].state != ZBP_ENABLED ||
	    !d->bps.bp[preexisting_id].installed) {
		/* Fallthrough collides with a known bp that is not
		 * currently armed.  Install it for this proceed only;
		 * we'll restore the previous logical state after. */
		if (d->bps.bp[preexisting_id].state == ZBP_DISABLED) {
			/* promote to a temp slot so we clear it afterwards */
			d->bps.bp[preexisting_id].temporary = 1;
			d->bps.bp[preexisting_id].state = ZBP_ENABLED;
			if (zbp_install(&d->target, &d->bps,
			    preexisting_id) < 0) {
				printf("temp breakpoint install failed\n");
				return -1;
			}
			temp_id = preexisting_id;
		}
	}

	/* If we are stopped on a permanent breakpoint, skip the
	 * internal single-step-and-reinstall path; the permanent bp
	 * will be reinstalled by hand after the temp fires. */
	if (d->stopped_bp >= 0 &&
	    !d->bps.bp[d->stopped_bp].temporary &&
	    d->bps.bp[d->stopped_bp].state == ZBP_ENABLED) {
		restore_perm_bp = d->stopped_bp;
		d->stopped_bp = -1;
	}

	if (ztarget_continue(&d->target) < 0) {
		printf("continue failed\n");
		return -1;
	}
	memset(&st, 0, sizeof(st));
	if (ztarget_wait(&d->target, &st) < 0) {
		printf("wait failed\n");
		return -1;
	}
	zdbg_after_wait(d, &st, &bp_id);

	/* Clean up our temp breakpoint if it is still present. */
	if (temp_id >= 0) {
		struct zbp *tb = &d->bps.bp[temp_id];
		if (tb->state != ZBP_EMPTY && tb->temporary) {
			if (d->stopped_bp == temp_id)
				d->stopped_bp = -1;
			(void)zbp_clear(&d->target, &d->bps, temp_id);
		}
	}

	/* Reinstall permanent bp at the call site if we bypassed
	 * the usual rearm path. */
	if (restore_perm_bp >= 0) {
		struct zbp *b = &d->bps.bp[restore_perm_bp];
		if (b->state == ZBP_ENABLED && !b->installed)
			(void)zbp_install(&d->target, &d->bps,
			    restore_perm_bp);
	}

	if (st.reason == ZSTOP_BREAKPOINT && target_stopped(d) &&
	    d->have_regs && d->regs.rip == fallthrough) {
		char ann[ZDBG_SYM_NAME_MAX + ZDBG_SYM_MODULE_MAX + 48];
		annot_addr(d, fallthrough, ann, sizeof(ann));
		printf("stopped: proceed rip=%016llx%s\n",
		    (unsigned long long)fallthrough, ann);
	} else {
		zstop_print(d, &st, bp_id);
	}
	return 0;
}

static int
cmd_p(struct zdbg *d, struct toks *t)
{
	uint64_t count = 1;
	uint64_t i;

	if (t->n >= 2) {
		if (zexpr_eval(t->v[1], &d->regs, &count) < 0 ||
		    count == 0) {
			printf("bad count\n");
			return -1;
		}
	}
	for (i = 0; i < count; i++) {
		int rc = cmd_p_once(d);
		if (rc < 0)
			return rc;
		if (!target_stopped(d))
			break;
	}
	return 0;
}

/* --- th -------------------------------------------------------- */

/*
 * Attempt to read RIP of the given thread by temporarily
 * switching the backend selection.  Restores the previous
 * selection before returning.  On failure *rip is left zero.
 */
static int
read_thread_rip(struct zdbg *d, uint64_t tid, uint64_t *rip)
{
	uint64_t saved;
	struct zregs r;

	if (rip == NULL)
		return -1;
	*rip = 0;
	saved = ztarget_current_thread(&d->target);
	if (ztarget_select_thread(&d->target, tid) < 0)
		return -1;
	memset(&r, 0, sizeof(r));
	if (ztarget_getregs(&d->target, &r) == 0)
		*rip = r.rip;
	/* restore previous selection best-effort */
	if (saved != tid && saved != 0)
		(void)ztarget_select_thread(&d->target, saved);
	return 0;
}

static void
print_thread_list(struct zdbg *d)
{
	int n;
	int i;
	uint64_t cur;

	n = ztarget_thread_count(&d->target);
	if (n <= 0) {
		printf(" no traced threads\n");
		return;
	}
	cur = ztarget_current_thread(&d->target);
	for (i = 0; i < n; i++) {
		struct zthread th;
		const char *s;
		char line[128];
		char ann[ZDBG_SYM_NAME_MAX + ZDBG_SYM_MODULE_MAX + 48];

		if (ztarget_thread_get(&d->target, i, &th) < 0)
			continue;
		switch (th.state) {
		case ZTHREAD_STOPPED:  s = "stopped"; break;
		case ZTHREAD_RUNNING:  s = "running"; break;
		case ZTHREAD_EXITED:   s = "exited "; break;
		case ZTHREAD_EMPTY:
		default:               s = "empty  "; break;
		}
		ann[0] = 0;
		line[0] = 0;
		if (th.state == ZTHREAD_STOPPED) {
			uint64_t rip = 0;
			if (read_thread_rip(d, th.tid, &rip) == 0 &&
			    rip != 0) {
				annot_addr(d, rip, ann, sizeof(ann));
				snprintf(line, sizeof(line),
				    "  rip=%016llx%s",
				    (unsigned long long)rip, ann);
			}
		}
		printf(" %c %d tid=%llu %s%s\n",
		    (th.tid == cur) ? '*' : ' ', i,
		    (unsigned long long)th.tid, s, line);
	}
}

/*
 * If a software breakpoint hit is still pending (int3 has been
 * uninstalled and RIP corrected on the stopping thread),
 * perform the internal single-step + reinstall on that thread
 * *before* the user changes selection.  Returns 0 on success,
 * -1 on error.
 */
static int
settle_stopped_bp_before_switch(struct zdbg *d)
{
	int id;
	struct zbp *b;
	struct zstop st;

	if (d->stopped_bp < 0)
		return 0;
	id = d->stopped_bp;
	if (id < 0 || id >= ZDBG_MAX_BREAKPOINTS)
		return 0;
	b = &d->bps.bp[id];
	d->stopped_bp = -1;
	if (b->state != ZBP_ENABLED)
		return 0;
	if (b->temporary) {
		(void)zbp_clear(&d->target, &d->bps, id);
		return 0;
	}
	/* Selected thread is the stopping thread at this point. */
	if (ztarget_singlestep(&d->target) < 0)
		return -1;
	memset(&st, 0, sizeof(st));
	if (ztarget_wait(&d->target, &st) < 0)
		return -1;
	if (st.reason != ZSTOP_SINGLESTEP)
		return 0;
	if (b->state == ZBP_ENABLED && !b->installed)
		(void)zbp_install(&d->target, &d->bps, id);
	return 0;
}

static int
cmd_th(struct zdbg *d, struct toks *t)
{
	uint64_t v;
	int n;

	if (!have_target(d)) {
		printf("no target\n");
		return -1;
	}

	if (t->n == 1) {
		print_thread_list(d);
		return 0;
	}

	if (zexpr_eval(t->v[1], NULL, &v) < 0) {
		printf("bad thread id\n");
		return -1;
	}

	/* Try exact TID first. */
	if (ztarget_select_thread(&d->target, v) == 0)
		goto selected;

	/* Fall back to index in the thread list. */
	n = ztarget_thread_count(&d->target);
	if ((int64_t)v >= 0 && (int)v < n) {
		struct zthread th;
		if (ztarget_thread_get(&d->target, (int)v, &th) == 0 &&
		    th.tid != 0) {
			if (ztarget_select_thread(&d->target, th.tid) == 0)
				goto selected;
		}
	}
	printf("no such thread: %s\n", t->v[1]);
	return -1;

selected:
	/*
	 * Settle any pending software breakpoint step before the
	 * user leaves the stopping thread.  Best-effort.
	 */
	(void)settle_stopped_bp_before_switch(d);
	/* Refresh cached regs from newly-selected stopped thread. */
	refresh_regs(d);
	printf("selected thread %llu\n",
	    (unsigned long long)ztarget_current_thread(&d->target));
	return 0;
}

/* --- lm -------------------------------------------------------- */

/*
 * `lm` shows full memory regions when available (Windows
 * VirtualQueryEx, Linux /proc/<pid>/maps), and falls back to
 * the module table.  Flags:
 *   -m   modules only (Windows debug-event modules; on Linux
 *        the same /proc table is shown)
 *   -r   memory regions only
 * An optional trailing address restricts output to the entry
 * containing that address.
 */
static int
cmd_lm(struct zdbg *d, struct toks *t)
{
	zaddr_t addr;
	const struct zmap *m;
	const struct zmap_table *mt;
	int want_modules = 0;
	int want_regions = 0;
	int argi = 1;

	if (!have_target(d)) {
		printf("no target\n");
		return -1;
	}
	if (t->n >= 2 && strcmp(t->v[1], "-m") == 0) {
		want_modules = 1;
		argi = 2;
	} else if (t->n >= 2 && strcmp(t->v[1], "-r") == 0) {
		want_regions = 1;
		argi = 2;
	}

	refresh_maps(d);
	refresh_syms(d);
	if (!want_modules)
		refresh_regions(d);

	/* Pick the table to display. */
	if (want_modules) {
		mt = d->have_maps ? &d->maps : NULL;
	} else if (want_regions) {
		mt = d->have_regions ? &d->regions : NULL;
	} else {
		/* Default: prefer regions, fall back to modules. */
		if (d->have_regions && d->regions.count > 0)
			mt = &d->regions;
		else if (d->have_maps)
			mt = &d->maps;
		else
			mt = NULL;
	}

	if (mt == NULL) {
		printf("could not read process maps\n");
		return -1;
	}

	if (t->n <= argi) {
		zmaps_print(mt);
		return 0;
	}
	if (eval_addr(d, t->v[argi], &addr) < 0) {
		printf("bad address\n");
		return -1;
	}
	m = zmaps_find_by_addr(mt, addr);
	if (m == NULL) {
		printf("%016llx: no mapping\n", (unsigned long long)addr);
		return -1;
	}
	zmaps_print_one((int)(m - mt->maps), m);
	return 0;
}

/* --- sym ------------------------------------------------------- */
static int
cmd_sym(struct zdbg *d, struct toks *t)
{
	const char *filter = NULL;

	if (t->n >= 2 && strcmp(t->v[1], "-r") == 0) {
		if (!have_target(d)) {
			printf("no target\n");
			return -1;
		}
		refresh_maps(d);
		refresh_syms(d);
		printf("loaded %d symbol(s)%s\n", d->syms.count,
		    d->syms.truncated ? " (truncated)" : "");
		return 0;
	}
	if (!d->have_syms) {
		if (have_target(d)) {
			refresh_maps(d);
			refresh_syms(d);
		}
	}
	if (!d->have_syms || d->syms.count == 0) {
		printf("no symbols loaded\n");
		return 0;
	}
	if (t->n >= 2)
		filter = t->v[1];
	zsyms_print(&d->syms, filter);
	return 0;
}

/* --- addr ------------------------------------------------------ */

/*
 * Resolve an address expression and print:
 *   <hex-addr> [<symbol+off>] [mapping-name]
 *
 * All pieces are best-effort: if symbols are not loaded or
 * maps cannot be read, those columns are omitted.
 */
static int
cmd_addr(struct zdbg *d, struct toks *t)
{
	zaddr_t addr;
	char ann[ZDBG_SYM_NAME_MAX + ZDBG_SYM_MODULE_MAX + 48];
	const struct zmap *m = NULL;
	const struct zmap *r = NULL;

	if (t->n < 2) {
		printf("usage: addr expr\n");
		return -1;
	}
	if (eval_addr(d, t->v[1], &addr) < 0) {
		printf("bad address\n");
		return -1;
	}
	annot_addr(d, addr, ann, sizeof(ann));
	if (have_target(d) && !d->have_maps)
		refresh_maps(d);
	if (have_target(d) && !d->have_regions)
		refresh_regions(d);
	if (d->have_maps)
		m = zmaps_find_by_addr(&d->maps, addr);
	if (d->have_regions)
		r = zmaps_find_by_addr(&d->regions, addr);
	printf("%016llx%s%s%s",
	    (unsigned long long)addr, ann,
	    m != NULL ? " " : "",
	    m != NULL ? m->name : "");
	if (r != NULL) {
		/*
		 * Show region perms/type.  When the module name from
		 * `maps` already covers this address, avoid repeating
		 * the same path; print only the perm/type block.
		 */
		if (m == NULL || strcmp(m->name, r->name) != 0)
			printf(" %s", r->name);
		printf(" %s %s", r->perms, zmaps_mem_type_str(r->mem_type));
	}
	printf("\n");
	return 0;
}

/* --- bt -------------------------------------------------------- */

/*
 * Conservative x86-64 user-space canonical check.  Strict
 * canonical rules require bits 63..47 of the address to all
 * match (sign extension of bit 47); for a frame-pointer walker
 * we care about user addresses only, which live in the lower
 * half [0x0000000000001000, 0x0000800000000000).  Rejecting
 * kernel-half and non-canonical values here also rejects zero
 * and the first page.
 */
static int
is_canonical_user_addr(uint64_t a)
{
	if (a < 0x1000)
		return 0;
	if (a >= 0x0000800000000000ULL)
		return 0;
	return 1;
}

static int
read_u64_le(struct ztarget *tgt, zaddr_t addr, uint64_t *out)
{
	uint8_t b[8];
	uint64_t v;
	int i;

	if (ztarget_read(tgt, addr, b, sizeof(b)) < 0)
		return -1;
	v = 0;
	for (i = 0; i < 8; i++)
		v |= (uint64_t)b[i] << (i * 8);
	*out = v;
	return 0;
}

static void
print_bt_frame(struct zdbg *d, int idx, zaddr_t rip)
{
	char ann[ZDBG_SYM_NAME_MAX + ZDBG_SYM_MODULE_MAX + 48];
	annot_addr(d, rip, ann, sizeof(ann));
	printf("#%-2d %016llx%s\n", idx, (unsigned long long)rip, ann);
}

static int
cmd_bt(struct zdbg *d, struct toks *t)
{
	uint64_t count = 16;
	uint64_t frame_delta_max = 0x100000ULL;	/* 1 MiB */
	zaddr_t rip;
	zaddr_t rbp;
	uint64_t i;

	if (!have_target(d) || !target_stopped(d)) {
		printf("no target\n");
		return -1;
	}
	refresh_regs(d);
	if (!d->have_regs) {
		printf("no registers\n");
		return -1;
	}
	if (t->n >= 2) {
		if (zexpr_eval(t->v[1], &d->regs, &count) < 0 ||
		    count == 0) {
			printf("bad count\n");
			return -1;
		}
	}
	if (have_target(d) && !d->have_maps)
		refresh_maps(d);

	rip = d->regs.rip;
	rbp = d->regs.rbp;

	/* frame 0 is always the current rip */
	print_bt_frame(d, 0, rip);

	for (i = 1; i < count; i++) {
		uint64_t next_rbp = 0;
		uint64_t retaddr = 0;

		if (!is_canonical_user_addr(rbp))
			break;
		if (read_u64_le(&d->target, rbp, &next_rbp) < 0)
			break;
		if (read_u64_le(&d->target, rbp + 8, &retaddr) < 0)
			break;
		if (retaddr == 0)
			break;
		if (!is_canonical_user_addr(retaddr))
			break;
		/* frame pointer must advance upward on x86-64 SysV */
		if (next_rbp <= rbp)
			break;
		if (next_rbp - rbp > frame_delta_max)
			break;
		/* if we have a map table, require retaddr to be executable
		 * and next_rbp to live in some mapping */
		if (d->have_maps) {
			const struct zmap *mr;
			const struct zmap *mb;
			mr = zmaps_find_by_addr(&d->maps, retaddr);
			mb = zmaps_find_by_addr(&d->maps, next_rbp);
			if (mr == NULL || mb == NULL)
				break;
			if (strchr(mr->perms, 'x') == NULL)
				break;
		}
		print_bt_frame(d, (int)i, retaddr);
		rbp = next_rbp;
		rip = retaddr;
	}
	return 0;
}

/* --- l / la / ld / k ------------------------------------------- */

/*
 * Report the synthetic initial stop after a successful launch
 * or attach.  The backend has already consumed the real
 * exec-trap/attach-stop internally; we just refresh cached
 * registers and print a compact "stopped: initial trap rip=..."
 * line so the user can immediately start inspecting the target.
 */
static void
report_initial_stop(struct zdbg *d)
{
	struct zstop st;

	memset(&st, 0, sizeof(st));
	st.reason = ZSTOP_INITIAL;
	if (ztarget_getregs(&d->target, &d->regs) == 0) {
		d->have_regs = 1;
		st.addr = d->regs.rip;
	}
	zstop_print(d, &st, -1);
	record_last_stop(d, &st);
}

static int
cmd_l(struct zdbg *d, struct toks *t)
{
	char *argv_local[MAX_TOKENS + 1];
	char **argv;
	int argc;
	int i;

	if (have_target(d)) {
		printf("target already active; use ld or k first\n");
		return -1;
	}

	if (t->n >= 2) {
		argc = t->n - 1;
		for (i = 0; i < argc; i++)
			argv_local[i] = t->v[i + 1];
		argv_local[argc] = NULL;
		argv = argv_local;
	} else {
		argc = d->target_argc;
		argv = d->target_argv;
	}
	if (argc <= 0 || argv == NULL || argv[0] == NULL) {
		printf("usage: l [path [args...]] (or pass target on "
		    "command line)\n");
		return -1;
	}

	if (ztarget_launch(&d->target, argc, argv) < 0) {
		printf("launch failed\n");
		return -1;
	}
	printf("launched pid %llu\n", (unsigned long long)d->target.pid);
	zhwbp_table_init(&d->hwbps);
	d->stopped_hwbp = -1;
	zpatch_table_init(&d->patches);
	clear_maps(d);
	clear_syms(d);
	zmaps_set_main_hint(&d->maps, argv[0]);
	refresh_maps(d);
	refresh_syms(d);
	report_initial_stop(d);
	return 0;
}

static int
cmd_la(struct zdbg *d, struct toks *t)
{
	uint64_t pid;

	if (t->n < 2) {
		printf("usage: la pid\n");
		return -1;
	}
	if (have_target(d)) {
		printf("target already active; use ld or k first\n");
		return -1;
	}
	if (zexpr_eval(t->v[1], NULL, &pid) < 0 || pid == 0) {
		printf("bad pid\n");
		return -1;
	}
	if (ztarget_attach(&d->target, pid) < 0) {
		printf("attach failed\n");
		return -1;
	}
	printf("attached pid %llu\n", (unsigned long long)d->target.pid);
	zhwbp_table_init(&d->hwbps);
	d->stopped_hwbp = -1;
	zpatch_table_init(&d->patches);
	clear_maps(d);
	clear_syms(d);
	refresh_maps(d);
	refresh_syms(d);
	report_initial_stop(d);
	return 0;
}

static int
cmd_ld(struct zdbg *d, struct toks *t)
{
	(void)t;
	if (!have_target(d)) {
		printf("no target\n");
		return -1;
	}
	/* Best-effort: clear hardware debug registers in the target
	 * before detaching so it does not keep stale breakpoints. */
	(void)zhwbp_clear_all(&d->target, &d->hwbps);
	if (ztarget_detach(&d->target) < 0) {
		printf("detach failed\n");
		return -1;
	}
	ztarget_init(&d->target);
	d->stopped_bp = -1;
	d->stopped_hwbp = -1;
	d->have_last_stop = 0;
	d->last_stop_hwbp = -1;
	d->last_stop_is_watch = 0;
	zhwbp_table_init(&d->hwbps);
	clear_maps(d);
	clear_syms(d);
	printf("detached\n");
	return 0;
}

static int
cmd_k(struct zdbg *d, struct toks *t)
{
	(void)t;
	if (!have_target(d)) {
		printf("no target\n");
		return -1;
	}
	if (ztarget_kill(&d->target) < 0) {
		printf("kill failed\n");
		return -1;
	}
	ztarget_init(&d->target);
	d->stopped_bp = -1;
	d->stopped_hwbp = -1;
	d->have_last_stop = 0;
	d->last_stop_hwbp = -1;
	d->last_stop_is_watch = 0;
	zhwbp_table_init(&d->hwbps);
	clear_maps(d);
	clear_syms(d);
	printf("killed\n");
	return 0;
}

/* --- sig / handle ---------------------------------------------- */

static int
cmd_sig(struct zdbg *d, struct toks *t)
{
	int sig = 0;
	int cur = 0;
	uint64_t tid;
	const struct zsig_policy *p;

	if (t->n >= 2 && strcmp(t->v[1], "-l") == 0) {
		int i;
		for (i = 1; i < ZDBG_MAX_SIGNALS; i++) {
			const char *name = zsig_name(i);
			if (strcmp(name, "SIG?") == 0)
				continue;
			printf(" %3d %s\n", i, name);
		}
		return 0;
	}

	if (!have_target(d)) {
		printf("no target\n");
		return -1;
	}
	if (!target_stopped(d)) {
		printf("target not stopped\n");
		return -1;
	}

	tid = ztarget_current_thread(&d->target);

	if (t->n == 1) {
		if (ztarget_get_pending_signal(&d->target, 0, &cur) < 0) {
			printf("pending signal not available\n");
			return -1;
		}
		if (cur == 0) {
			printf("thread %llu pending signal: none\n",
			    (unsigned long long)tid);
			return 0;
		}
		p = zsig_get_policy(&d->sigs, cur);
		printf("thread %llu pending signal: %s(%d), pass=%s\n",
		    (unsigned long long)tid, zsig_name(cur), cur,
		    (p != NULL && p->pass) ? "yes" : "no");
		return 0;
	}

	if (zsig_parse(t->v[1], &sig) < 0) {
		printf("unknown signal: %s\n", t->v[1]);
		return -1;
	}
	if (ztarget_set_pending_signal(&d->target, 0, sig) < 0) {
		printf("pending signal set not available\n");
		return -1;
	}
	if (sig == 0)
		printf("pending signal cleared\n");
	else
		printf("pending signal set to %s(%d)\n",
		    zsig_name(sig), sig);
	return 0;
}

/*
 * Parse one stop/pass/print option token into set flag and
 * value pair.  Returns 0 on match, -1 on unknown word.
 */
static int
parse_handle_opt(const char *s,
    int *set_stop, int *stop,
    int *set_pass, int *pass,
    int *set_print, int *print)
{
	if (strcmp(s, "stop") == 0)     { *set_stop = 1;  *stop = 1;  return 0; }
	if (strcmp(s, "nostop") == 0)   { *set_stop = 1;  *stop = 0;  return 0; }
	if (strcmp(s, "pass") == 0)     { *set_pass = 1;  *pass = 1;  return 0; }
	if (strcmp(s, "nopass") == 0)   { *set_pass = 1;  *pass = 0;  return 0; }
	if (strcmp(s, "print") == 0)    { *set_print = 1; *print = 1; return 0; }
	if (strcmp(s, "noprint") == 0)  { *set_print = 1; *print = 0; return 0; }
	return -1;
}

static int
cmd_handle(struct zdbg *d, struct toks *t)
{
	int sig = 0;
	uint32_t xcode = 0;
	int is_exc = 0;
	const struct zsig_policy *p;
	const struct zexc_policy *xp;
	int set_stop = 0, set_pass = 0, set_print = 0;
	int stop = 0, pass = 0, print = 0;
	int i;

	if (t->n == 1) {
#if defined(_WIN32)
		zexc_print_table(&d->excs);
#else
		zsig_print_table(&d->sigs);
#endif
		return 0;
	}
	/*
	 * Try signal first, then exception.  Both tables are
	 * available on every platform so that configuration
	 * scripts do not care about host OS, but output routing
	 * honors the native meaning: POSIX names update signals,
	 * Windows exception names update the exception table.
	 */
	if (zsig_parse(t->v[1], &sig) == 0 && sig != 0) {
		is_exc = 0;
	} else if (zexc_parse(t->v[1], &xcode) == 0) {
		is_exc = 1;
	} else {
		printf("unknown signal/exception: %s\n", t->v[1]);
		return -1;
	}
	if (t->n == 2) {
		if (is_exc) {
			xp = zexc_get_policy(&d->excs, xcode);
			if (xp == NULL) {
				printf("no policy\n");
				return -1;
			}
			printf(" Exception                          "
			    "Stop Pass Print\n");
			zexc_print_one(xcode, xp);
			return 0;
		}
		p = zsig_get_policy(&d->sigs, sig);
		if (p == NULL) {
			printf("unknown signal: %s\n", t->v[1]);
			return -1;
		}
		printf(" Signal    Stop Pass Print\n");
		zsig_print_one(sig, p);
		return 0;
	}
	for (i = 2; i < t->n; i++) {
		if (parse_handle_opt(t->v[i],
		    &set_stop, &stop,
		    &set_pass, &pass,
		    &set_print, &print) < 0) {
			printf("bad handle option: %s\n", t->v[i]);
			return -1;
		}
	}
	if (is_exc) {
		if (zexc_set_policy(&d->excs, xcode,
		    set_stop, stop, set_pass, pass, set_print, print) < 0) {
			printf("exception policy table full\n");
			return -1;
		}
		xp = zexc_get_policy(&d->excs, xcode);
		printf(" Exception                          "
		    "Stop Pass Print\n");
		zexc_print_one(xcode, xp);
		return 0;
	}
	if (zsig_set_policy(&d->sigs, sig,
	    set_stop, stop, set_pass, pass, set_print, print) < 0) {
		printf("bad signal\n");
		return -1;
	}
	p = zsig_get_policy(&d->sigs, sig);
	printf(" Signal    Stop Pass Print\n");
	zsig_print_one(sig, p);
	return 0;
}

/*
 * cmd_ex: Windows exception pending-event control.
 *
 *   ex                        show pending exception on current thread
 *   ex -l                     list known Windows exception names/codes
 *   ex 0                      suppress pending exception (DBG_CONTINUE)
 *   ex pass | nopass          change pending exception continuation
 *   ex CODE pass | nopass     same, with an optional code match guard
 *
 * On non-Windows backends the underlying ztarget calls return
 * -1 and `ex` reports "Windows exception control unavailable on
 * this backend".
 */
static int
cmd_ex(struct zdbg *d, struct toks *t)
{
	uint64_t tid;
	uint32_t code = 0;
	int fc = 0;
	int cur_pass = 0;

	if (t->n >= 2 && strcmp(t->v[1], "-l") == 0) {
		zexc_print_names();
		return 0;
	}

	if (!have_target(d)) {
		printf("no target\n");
		return -1;
	}
	if (!target_stopped(d)) {
		printf("target not stopped\n");
		return -1;
	}

	tid = ztarget_current_thread(&d->target);

	if (t->n == 1) {
		if (ztarget_get_pending_exception(&d->target, 0,
		    &code, &fc, &cur_pass) < 0) {
			/*
			 * Could be Linux (API unsupported) or Windows
			 * with no real exception pending.  The former
			 * should say "unavailable"; we can only
			 * detect the difference by trying a clear
			 * with no active exception.  Report "none"
			 * for the common case and let non-Windows
			 * users see the platform-neutral message.
			 */
#if defined(_WIN32)
			printf("thread %llu pending exception: none\n",
			    (unsigned long long)tid);
#else
			printf("Windows exception control unavailable "
			    "on this backend\n");
#endif
			return 0;
		}
		printf("thread %llu pending exception: %s(0x%08x)"
		    " %s pass=%s\n",
		    (unsigned long long)tid, zexc_name(code),
		    (unsigned int)code,
		    fc ? "first-chance" : "second-chance",
		    cur_pass ? "yes" : "no");
		return 0;
	}

	/* ex 0 -> clear/suppress */
	if (strcmp(t->v[1], "0") == 0) {
		if (ztarget_clear_pending_exception(&d->target, 0) < 0) {
			printf("Windows exception control unavailable "
			    "on this backend\n");
			return -1;
		}
		printf("pending exception will be suppressed with "
		    "DBG_CONTINUE\n");
		return 0;
	}

	/* ex pass | nopass */
	if (strcmp(t->v[1], "pass") == 0 || strcmp(t->v[1], "nopass") == 0) {
		int pass = strcmp(t->v[1], "pass") == 0 ? 1 : 0;
		if (ztarget_set_pending_exception(&d->target, 0,
		    0, -1, pass) < 0) {
			printf("Windows exception control unavailable "
			    "on this backend or no exception pending\n");
			return -1;
		}
		printf("pending exception: pass=%s (%s)\n",
		    pass ? "yes" : "no",
		    pass ? "DBG_EXCEPTION_NOT_HANDLED" : "DBG_CONTINUE");
		return 0;
	}

	/* ex CODE pass|nopass */
	if (t->n >= 3) {
		uint32_t want;
		int pass;
		if (zexc_parse(t->v[1], &want) < 0) {
			printf("unknown exception: %s\n", t->v[1]);
			return -1;
		}
		if (strcmp(t->v[2], "pass") == 0)
			pass = 1;
		else if (strcmp(t->v[2], "nopass") == 0)
			pass = 0;
		else {
			printf("expected pass or nopass, got %s\n",
			    t->v[2]);
			return -1;
		}
		if (ztarget_get_pending_exception(&d->target, 0, &code,
		    &fc, &cur_pass) < 0) {
			printf("Windows exception control unavailable "
			    "on this backend or no exception pending\n");
			return -1;
		}
		if (code != want) {
			printf("pending exception is 0x%08x, not 0x%08x\n",
			    (unsigned int)code, (unsigned int)want);
			return -1;
		}
		if (ztarget_set_pending_exception(&d->target, 0,
		    want, fc, pass) < 0) {
			printf("set pending exception failed\n");
			return -1;
		}
		printf("pending exception %s(0x%08x): pass=%s\n",
		    zexc_name(code), (unsigned int)code,
		    pass ? "yes" : "no");
		return 0;
	}

	printf("usage: ex | ex -l | ex 0 | ex pass|nopass"
	    " | ex CODE pass|nopass\n");
	return -1;
}

/* --- pl / pu / pr / pf / ps / pw ------------------------------- */

static int
parse_patch_id(const char *s, int *idp)
{
	uint64_t v;
	if (zexpr_eval(s, NULL, &v) < 0)
		return -1;
	if (v >= ZDBG_MAX_PATCHES)
		return -1;
	*idp = (int)v;
	return 0;
}

static const char *
patch_state_str(enum zpatch_state st)
{
	switch (st) {
	case ZPATCH_APPLIED:  return "applied ";
	case ZPATCH_REVERTED: return "reverted";
	case ZPATCH_EMPTY:
	default:              return "empty   ";
	}
}

/*
 * Render up to max_bytes hex bytes into buf; if the patch is
 * longer, a trailing "..." is appended.  Output is always
 * NUL-terminated.
 */
static void
format_patch_bytes(char *buf, size_t buflen, const uint8_t *bytes,
    size_t len, size_t max_bytes)
{
	size_t pos = 0;
	size_t n = len < max_bytes ? len : max_bytes;
	size_t i;

	if (buf == NULL || buflen == 0)
		return;
	buf[0] = 0;
	for (i = 0; i < n && pos + 3 < buflen; i++) {
		int w = snprintf(buf + pos, buflen - pos,
		    i + 1 == n ? "%02x" : "%02x ", bytes[i]);
		if (w < 0)
			return;
		pos += (size_t)w;
	}
	if (len > max_bytes && pos + 4 < buflen)
		snprintf(buf + pos, buflen - pos, " ...");
}

static void
print_patch_row(struct zdbg *d, int id, const struct zpatch *p)
{
	char oldhex[64];
	char newhex[64];
	char ann[ZDBG_SYM_NAME_MAX + ZDBG_SYM_MODULE_MAX + 48];

	format_patch_bytes(oldhex, sizeof(oldhex), p->old_bytes, p->len, 16);
	format_patch_bytes(newhex, sizeof(newhex), p->new_bytes, p->len, 16);
	annot_addr(d, p->addr, ann, sizeof(ann));
	printf(" %3d %s %016llx len=%zu %-4s old=%s new=%s",
	    id, patch_state_str(p->state),
	    (unsigned long long)p->addr, p->len,
	    p->origin[0] ? p->origin : "?",
	    oldhex, newhex);
	if (p->has_file) {
		if (p->has_rva)
			printf(" file=%s+rva:0x%llx/file:0x%llx",
			    p->file,
			    (unsigned long long)p->rva,
			    (unsigned long long)p->file_off);
		else
			printf(" file=%s+0x%llx", p->file,
			    (unsigned long long)p->file_off);
	}
	if (ann[0])
		printf("%s", ann);
	printf("\n");
}

static int
cmd_pl(struct zdbg *d, struct toks *t)
{
	int i;
	int any = 0;

	(void)t;
	for (i = 0; i < ZDBG_MAX_PATCHES; i++) {
		const struct zpatch *p = &d->patches.patches[i];
		if (p->state == ZPATCH_EMPTY)
			continue;
		print_patch_row(d, i, p);
		any = 1;
	}
	if (!any)
		printf(" no patches\n");
	return 0;
}

/*
 * Apply one direction of a patch: if revert=1 write old_bytes,
 * otherwise write new_bytes.  Updates patch state accordingly.
 * Returns 0 on success, -1 on error (with a message printed).
 */
static int
patch_apply_dir(struct zdbg *d, int id, int revert)
{
	const struct zpatch *p;
	const uint8_t *src;

	if (zpatch_get(&d->patches, id, &p) < 0) {
		printf("no patch %d\n", id);
		return -1;
	}
	if (revert) {
		if (p->state != ZPATCH_APPLIED) {
			printf("patch %d already reverted\n", id);
			return -1;
		}
	} else {
		if (p->state != ZPATCH_REVERTED) {
			printf("patch %d already applied\n", id);
			return -1;
		}
	}
	src = revert ? p->old_bytes : p->new_bytes;
	if (ztarget_write(&d->target, p->addr, src, p->len) < 0) {
		printf("write failed\n");
		return -1;
	}
	(void)ztarget_flush_icache(&d->target, p->addr, p->len);
	if (revert)
		(void)zpatch_mark_reverted(&d->patches, id);
	else
		(void)zpatch_mark_applied(&d->patches, id);
	printf("patch %d %s\n", id, revert ? "reverted" : "reapplied");
	return 0;
}

static int
cmd_pu(struct zdbg *d, struct toks *t)
{
	int id;
	int i;

	if (t->n < 2) {
		printf("usage: pu id|*\n");
		return -1;
	}
	if (!have_target(d) || !target_stopped(d)) {
		printf("no stopped target\n");
		return -1;
	}
	if (strcmp(t->v[1], "*") == 0) {
		/* revert applied patches in reverse order */
		for (i = ZDBG_MAX_PATCHES - 1; i >= 0; i--) {
			const struct zpatch *p = &d->patches.patches[i];
			if (p->state != ZPATCH_APPLIED)
				continue;
			(void)patch_apply_dir(d, i, 1);
		}
		return 0;
	}
	if (parse_patch_id(t->v[1], &id) < 0) {
		printf("bad id\n");
		return -1;
	}
	return patch_apply_dir(d, id, 1);
}

static int
cmd_pr(struct zdbg *d, struct toks *t)
{
	int id;
	int i;

	if (t->n < 2) {
		printf("usage: pr id|*\n");
		return -1;
	}
	if (!have_target(d) || !target_stopped(d)) {
		printf("no stopped target\n");
		return -1;
	}
	if (strcmp(t->v[1], "*") == 0) {
		/* reapply in ascending order */
		for (i = 0; i < ZDBG_MAX_PATCHES; i++) {
			const struct zpatch *p = &d->patches.patches[i];
			if (p->state != ZPATCH_REVERTED)
				continue;
			(void)patch_apply_dir(d, i, 0);
		}
		return 0;
	}
	if (parse_patch_id(t->v[1], &id) < 0) {
		printf("bad id\n");
		return -1;
	}
	return patch_apply_dir(d, id, 0);
}

static int
cmd_pf(struct zdbg *d, struct toks *t)
{
	int id;
	const struct zpatch *p;
	char ann[ZDBG_SYM_NAME_MAX + ZDBG_SYM_MODULE_MAX + 48];

	if (t->n < 2 || parse_patch_id(t->v[1], &id) < 0) {
		printf("usage: pf id\n");
		return -1;
	}
	if (zpatch_get(&d->patches, id, &p) < 0) {
		printf("no patch %d\n", id);
		return -1;
	}
	if (!p->has_file) {
		printf("patch %d has no safe file backing\n", id);
		return 0;
	}
	annot_addr(d, p->addr, ann, sizeof(ann));
	printf("patch %d:\n", id);
	printf("  va:       %016llx%s\n",
	    (unsigned long long)p->addr, ann);
	printf("  len:      %zu\n", p->len);
	printf("  file:     %s\n", p->file);
	if (p->has_rva)
		printf("  rva:      0x%llx\n",
		    (unsigned long long)p->rva);
	printf("  fileoff:  0x%llx\n", (unsigned long long)p->file_off);
	printf("  state:    %s\n",
	    p->state == ZPATCH_APPLIED ? "applied" :
	    p->state == ZPATCH_REVERTED ? "reverted" : "empty");
	return 0;
}

/*
 * Write the full new_bytes of one patch to the given path as a
 * raw file.  Overwrites the file if it exists.  Returns 0 on
 * success, -1 on failure.
 */
static int
save_patch_raw(const struct zpatch *p, const char *path)
{
	FILE *f;
	size_t w;

	f = fopen(path, "wb");
	if (f == NULL) {
		printf("could not open %s for writing\n", path);
		return -1;
	}
	w = fwrite(p->new_bytes, 1, p->len, f);
	if (w != p->len) {
		printf("short write to %s\n", path);
		fclose(f);
		return -1;
	}
	if (fclose(f) != 0) {
		printf("close failed on %s\n", path);
		return -1;
	}
	return 0;
}

static void
fprint_hex_bytes(FILE *f, const uint8_t *b, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++)
		fprintf(f, "%s%02x", i == 0 ? "" : " ", b[i]);
}

/*
 * Write the full patch table to the given path as a simple
 * textual script.  Only ZPATCH_APPLIED and ZPATCH_REVERTED
 * entries are emitted.  Returns 0 on success, -1 on failure.
 */
static int
save_patch_script(const struct zpatch_table *pt, const char *path)
{
	FILE *f;
	int i;

	f = fopen(path, "w");
	if (f == NULL) {
		printf("could not open %s for writing\n", path);
		return -1;
	}
	fprintf(f, "# zdbg patch script v1\n");
	fprintf(f, "# addr len origin file fileoff\n");
	for (i = 0; i < ZDBG_MAX_PATCHES; i++) {
		const struct zpatch *p = &pt->patches[i];
		if (p->state == ZPATCH_EMPTY)
			continue;
		fprintf(f, "\npatch %016llx %zu %s",
		    (unsigned long long)p->addr, p->len,
		    p->origin[0] ? p->origin : "?");
		if (p->has_file)
			fprintf(f, " %s 0x%llx",
			    p->file, (unsigned long long)p->file_off);
		fprintf(f, "\nstate %s\n",
		    p->state == ZPATCH_APPLIED ? "applied" : "reverted");
		fprintf(f, "old ");
		fprint_hex_bytes(f, p->old_bytes, p->len);
		fprintf(f, "\nnew ");
		fprint_hex_bytes(f, p->new_bytes, p->len);
		fprintf(f, "\n");
	}
	if (fclose(f) != 0) {
		printf("close failed on %s\n", path);
		return -1;
	}
	return 0;
}

static int
cmd_ps(struct zdbg *d, struct toks *t)
{
	int id;
	const struct zpatch *p;

	if (t->n < 3) {
		printf("usage: ps id|* path\n");
		return -1;
	}
	if (strcmp(t->v[1], "*") == 0) {
		if (save_patch_script(&d->patches, t->v[2]) < 0)
			return -1;
		printf("wrote patch script to %s\n", t->v[2]);
		return 0;
	}
	if (parse_patch_id(t->v[1], &id) < 0) {
		printf("bad id\n");
		return -1;
	}
	if (zpatch_get(&d->patches, id, &p) < 0) {
		printf("no patch %d\n", id);
		return -1;
	}
	if (save_patch_raw(p, t->v[2]) < 0)
		return -1;
	printf("wrote patch %d (%zu bytes) to %s\n", id, p->len, t->v[2]);
	return 0;
}

/*
 * Write one patch back to its mapped file, but only if the
 * on-disk bytes at file_off still match the recorded old_bytes.
 * This is intentionally conservative: it protects against
 * overwriting a file that has been rebuilt/changed since the
 * patch was recorded.
 */
static int
write_patch_to_file(const struct zpatch *p)
{
	FILE *f;
	uint8_t cur[ZDBG_PATCH_MAX_BYTES];
	size_t r;

	if (!p->has_file || p->file[0] == 0) {
		printf("patch has no file backing\n");
		return -1;
	}
	if (p->state != ZPATCH_APPLIED) {
		printf("patch not applied\n");
		return -1;
	}
	f = fopen(p->file, "r+b");
	if (f == NULL) {
		printf("could not open %s for read/write\n", p->file);
		return -1;
	}
	if (fseek(f, (long)p->file_off, SEEK_SET) != 0) {
		printf("seek failed on %s\n", p->file);
		fclose(f);
		return -1;
	}
	r = fread(cur, 1, p->len, f);
	if (r != p->len) {
		printf("short read from %s\n", p->file);
		fclose(f);
		return -1;
	}
	if (memcmp(cur, p->old_bytes, p->len) != 0) {
		printf("file bytes do not match expected old bytes; "
		    "refusing\n");
		fclose(f);
		return -1;
	}
	if (fseek(f, (long)p->file_off, SEEK_SET) != 0) {
		printf("seek failed on %s\n", p->file);
		fclose(f);
		return -1;
	}
	if (fwrite(p->new_bytes, 1, p->len, f) != p->len) {
		printf("write failed on %s\n", p->file);
		fclose(f);
		return -1;
	}
	if (fclose(f) != 0) {
		printf("close failed on %s\n", p->file);
		return -1;
	}
	return 0;
}

static const char *
pw_warning_for(int has_pe)
{
	if (has_pe)
		return "warning: writing mapped PE file bytes on disk; "
		    "no PE checksum, certificate, signature, "
		    "relocation, or metadata is updated";
	return "warning: writing mapped file bytes on disk; no ELF "
	    "metadata is updated";
}

static int
cmd_pw(struct zdbg *d, struct toks *t)
{
	int id;
	const struct zpatch *p;
	int i;
	int nok = 0;
	int nfail = 0;
	int any_pe;

	if (t->n < 2) {
		printf("usage: pw id|*\n");
		return -1;
	}
	if (strcmp(t->v[1], "*") == 0) {
		any_pe = 0;
		for (i = 0; i < ZDBG_MAX_PATCHES; i++) {
			p = &d->patches.patches[i];
			if (p->state != ZPATCH_APPLIED)
				continue;
			if (!p->has_file)
				continue;
			if (p->has_rva) {
				any_pe = 1;
				break;
			}
		}
		printf("%s\n", pw_warning_for(any_pe));
		for (i = 0; i < ZDBG_MAX_PATCHES; i++) {
			p = &d->patches.patches[i];
			if (p->state != ZPATCH_APPLIED)
				continue;
			if (!p->has_file)
				continue;
			if (write_patch_to_file(p) == 0) {
				printf("wrote patch %d to %s at file "
				    "offset 0x%llx\n",
				    i, p->file,
				    (unsigned long long)p->file_off);
				nok++;
			} else {
				printf("patch %d: failed\n", i);
				nfail++;
			}
		}
		printf("pw: %d ok, %d failed\n", nok, nfail);
		return 0;
	}
	if (parse_patch_id(t->v[1], &id) < 0) {
		printf("bad id\n");
		return -1;
	}
	if (zpatch_get(&d->patches, id, &p) < 0) {
		printf("no patch %d\n", id);
		return -1;
	}
	if (!p->has_file) {
		printf("patch %d has no safe file backing\n", id);
		return -1;
	}
	printf("%s\n", pw_warning_for(p->has_rva));
	if (write_patch_to_file(p) < 0)
		return -1;
	printf("wrote patch %d to %s at file offset 0x%llx\n",
	    id, p->file, (unsigned long long)p->file_off);
	return 0;
}

/* --- script sourcing ------------------------------------------ */

/*
 * Return 1 if the line, after leading whitespace, is empty or
 * starts with a `;`/`#` comment marker.  These lines are
 * skipped during script execution and verbose echoing.
 */
static int
script_line_is_blank_or_comment(const char *line)
{
	const char *p = line;

	while (*p == ' ' || *p == '\t')
		p++;
	if (*p == 0 || *p == ';' || *p == '#')
		return 1;
	return 0;
}

/*
 * Internal: execute commands from `fp`.  `name` is used in
 * diagnostics (file path or "<stdin>").  See zcmd_source_file()
 * for return values.
 */
static int
zcmd_source_stream_internal(struct zdbg *d, FILE *fp, const char *name)
{
	char line[ZDBG_SCRIPT_LINE_MAX];
	int lineno = 0;
	int rc = 0;

	if (d == NULL || fp == NULL || name == NULL)
		return -2;
	if (d->source_depth >= ZDBG_MAX_SOURCE_DEPTH) {
		fprintf(stderr, "source nesting too deep\n");
		return -2;
	}
	d->source_depth++;

	for (;;) {
		size_t n;
		int cmd_rc;

		if (fgets(line, sizeof(line), fp) == NULL)
			break;
		lineno++;
		n = strlen(line);
		/*
		 * Detect over-long lines: fgets stops at a newline
		 * or sizeof(line)-1 bytes.  If we filled the buffer
		 * and did not see a newline, the line was too long.
		 */
		if (n == sizeof(line) - 1 && line[n - 1] != '\n') {
			int ch;

			fprintf(stderr, "%s:%d: line too long\n",
			    name, lineno);
			/* Drain the rest of the over-long line. */
			while ((ch = fgetc(fp)) != EOF && ch != '\n')
				;
			d->had_error = 1;
			rc = -1;
			break;
		}
		while (n > 0 &&
		    (line[n - 1] == '\n' || line[n - 1] == '\r'))
			line[--n] = 0;

		if (script_line_is_blank_or_comment(line))
			continue;

		if (d->verbose)
			printf("+ %s\n", line);

		cmd_rc = zcmd_exec(d, line);
		d->last_status = cmd_rc;
		if (cmd_rc == RC_QUIT) {
			d->quit_requested = 1;
			break;
		}
		if (cmd_rc != 0) {
			fprintf(stderr,
			    "%s:%d: command failed: %s\n",
			    name, lineno, line);
			d->had_error = 1;
			rc = -1;
			break;
		}
		if (d->quit_requested)
			break;
	}

	d->source_depth--;
	return rc;
}

int
zcmd_source_file(struct zdbg *d, const char *path)
{
	FILE *fp;
	int rc;

	if (d == NULL || path == NULL)
		return -2;
	fp = fopen(path, "r");
	if (fp == NULL) {
		fprintf(stderr, "cannot open script: %s\n", path);
		return -2;
	}
	rc = zcmd_source_stream_internal(d, fp, path);
	fclose(fp);
	return rc;
}

int
zcmd_source_stream(struct zdbg *d, FILE *fp, const char *name)
{
	return zcmd_source_stream_internal(d, fp,
	    name != NULL ? name : "<stream>");
}

static int
cmd_source(struct zdbg *d, struct toks *t)
{
	struct cmd_qargs a;
	const char *line;

	if (t->n < 2 && (t->rest == NULL || t->rest[0] == 0)) {
		printf("usage: source path\n");
		return -1;
	}
	/*
	 * Re-parse the original line with the quote-aware splitter
	 * so paths containing spaces survive ("C:\Tmp\my script").
	 */
	line = t->orig;
	while (*line == ' ' || *line == '\t')
		line++;
	/* skip the command word ("source" or ".") */
	while (*line && *line != ' ' && *line != '\t')
		line++;
	while (*line == ' ' || *line == '\t')
		line++;
	if (*line == 0) {
		printf("usage: source path\n");
		return -1;
	}
	if (cmd_qsplit(line, &a) < 0) {
		printf("source: argument too long\n");
		return -1;
	}
	if (a.n < 1) {
		printf("usage: source path\n");
		return -1;
	}
	return zcmd_source_file(d, a.v[0]) == 0 ? 0 : -1;
}

/* --- check / assert / expect ---------------------------------- */

/*
 * Script-friendly assertion command family.  Every check returns
 * 0 on pass and -1 on failure.  Successful checks are silent;
 * failed ones print a single line beginning with "check failed:"
 * (or "assert failed:" / "expect failed:" when invoked under the
 * alias).  The script driver naturally stops on the first failure
 * because zcmd_source_file() already aborts on a nonzero command
 * return value.
 *
 * Subcommands intentionally do not introduce a scripting language:
 * arguments are resolved with the same tiny expression evaluator
 * used elsewhere (eval_addr / zexpr_eval).
 */

static const char *check_word = "check";

/*
 * Map a stop-reason name to enum zstop_reason.
 *
 *   initial breakpoint singlestep signal exception exit error
 *   hwbp watchpoint               (mapped to existing reasons)
 *
 * Returns 0 on success and writes *out, -1 on unknown name.
 * Sets *want_hwbp to 1 for "hwbp" and *want_watch to 1 for
 * "watchpoint", since both arrive over BREAKPOINT/SINGLESTEP
 * but are distinguished via d->last_stop_hwbp/last_stop_is_watch.
 */
static int
check_parse_stop_reason(const char *s, enum zstop_reason *out,
    int *want_hwbp, int *want_watch)
{
	if (s == NULL || out == NULL)
		return -1;
	*want_hwbp = 0;
	*want_watch = 0;
	if (strcmp(s, "initial") == 0) {
		*out = ZSTOP_INITIAL;
		return 0;
	}
	if (strcmp(s, "breakpoint") == 0 || strcmp(s, "bp") == 0) {
		*out = ZSTOP_BREAKPOINT;
		return 0;
	}
	if (strcmp(s, "singlestep") == 0 || strcmp(s, "step") == 0) {
		*out = ZSTOP_SINGLESTEP;
		return 0;
	}
	if (strcmp(s, "signal") == 0) {
		*out = ZSTOP_SIGNAL;
		return 0;
	}
	if (strcmp(s, "exception") == 0) {
		*out = ZSTOP_EXCEPTION;
		return 0;
	}
	if (strcmp(s, "exit") == 0) {
		*out = ZSTOP_EXIT;
		return 0;
	}
	if (strcmp(s, "error") == 0) {
		*out = ZSTOP_ERROR;
		return 0;
	}
	if (strcmp(s, "hwbp") == 0 || strcmp(s, "hwbreak") == 0) {
		*out = ZSTOP_BREAKPOINT;
		*want_hwbp = 1;
		return 0;
	}
	if (strcmp(s, "watchpoint") == 0 || strcmp(s, "watch") == 0) {
		*out = ZSTOP_BREAKPOINT;
		*want_hwbp = 1;
		*want_watch = 1;
		return 0;
	}
	return -1;
}

/*
 * Test whether `tok` is a pure numeric token that the symbol
 * lookup commands should refuse to treat as a symbol name.  This
 * matches the input forms accepted by zexpr_eval as numbers:
 * default-hex digits, "0x" prefix, "h" suffix, "#" decimal.
 *
 * Returns 1 on numeric, 0 on a real (or empty) name.
 */
static int
check_token_is_numeric(const char *s)
{
	uint64_t v;

	if (s == NULL || *s == 0)
		return 0;
	return zexpr_eval(s, NULL, &v) == 0 ? 1 : 0;
}

/*
 * Look up a symbol expression `name` (optionally module:name)
 * without falling back to numeric/map/register paths.  Pure
 * numeric tokens are rejected so `check symbol 401000` fails.
 *
 * Returns 0 on found and writes *out, -1 on not-found, -2 on
 * ambiguous, -3 on numeric input.
 */
static int
check_resolve_symbol_strict(struct zdbg *d, const char *name, zaddr_t *out)
{
	if (name == NULL || *name == 0)
		return -1;
	if (check_token_is_numeric(name))
		return -3;
	if (!d->have_syms)
		return -1;
	return zsyms_resolve(&d->syms, d->have_maps ? &d->maps : NULL,
	    name, out);
}

static int
check_fail(const char *fmt, ...)
{
	va_list ap;

	printf("%s failed: ", check_word);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
	return -1;
}

static int
check_target(struct zdbg *d)
{
	if (have_target(d))
		return 0;
	return check_fail("no target");
}

static int
check_stopped(struct zdbg *d)
{
	if (!have_target(d))
		return check_fail("no target");
	if (!target_stopped(d))
		return check_fail("target not stopped");
	return 0;
}

static int
check_running(struct zdbg *d)
{
	if (!have_target(d))
		return check_fail("no target");
	if (d->target.state != ZTARGET_RUNNING)
		return check_fail("target not running");
	return 0;
}

static int
check_exited(struct zdbg *d, int has_code, int code)
{
	int got;

	if (!d->have_last_stop ||
	    d->last_stop.reason != ZSTOP_EXIT) {
		if (d->target.state != ZTARGET_EXITED)
			return check_fail("target has not exited");
	}
	if (!has_code)
		return 0;
	got = d->have_last_stop ? d->last_stop.code : 0;
	if (got != code)
		return check_fail(
		    "expected exit code %d, got %d", code, got);
	return 0;
}

static int
check_stop(struct zdbg *d, const char *reason_name)
{
	enum zstop_reason want;
	int want_hwbp = 0;
	int want_watch = 0;

	if (!d->have_last_stop)
		return check_fail("no last stop");
	if (check_parse_stop_reason(reason_name, &want, &want_hwbp,
	    &want_watch) < 0)
		return check_fail("unknown stop reason: %s",
		    reason_name);
	if (d->last_stop.reason != want) {
		/* Allow ZSTOP_SINGLESTEP for hwbp/watch on Windows
		 * where hardware traps surface as single-step. */
		if (want_hwbp && d->last_stop.reason == ZSTOP_SINGLESTEP)
			/* fall through to hwbp/watch validation */;
		else
			return check_fail("stop reason mismatch");
	}
	if (want_hwbp && d->last_stop_hwbp < 0)
		return check_fail("last stop is not a hardware stop");
	if (want_watch && !d->last_stop_is_watch)
		return check_fail("last stop is not a watchpoint");
	return 0;
}

static int
check_thread(struct zdbg *d, const char *tok)
{
	uint64_t cur;

	if (!have_target(d))
		return check_fail("no target");
	cur = ztarget_current_thread(&d->target);
	if (tok == NULL || strcmp(tok, "current") == 0) {
		if (cur == 0)
			return check_fail("no current thread");
		return 0;
	}
	{
		uint64_t want;
		if (zexpr_eval(tok, NULL, &want) < 0)
			return check_fail("bad tid: %s", tok);
		if (cur != want)
			return check_fail(
			    "thread expected %llu, got %llu",
			    (unsigned long long)want,
			    (unsigned long long)cur);
	}
	return 0;
}

static int
check_reg(struct zdbg *d, const char *name, const char *expr)
{
	uint64_t got = 0;
	zaddr_t want = 0;

	if (!have_target(d))
		return check_fail("no target");
	if (!target_stopped(d))
		return check_fail("target not stopped");
	refresh_regs(d);
	if (zregs_get_by_name(&d->regs, name, &got) < 0)
		return check_fail("unknown register: %s", name);
	if (eval_addr(d, expr, &want) < 0) {
		uint64_t v;
		if (zexpr_eval(expr, &d->regs, &v) < 0)
			return check_fail("bad value: %s", expr);
		want = (zaddr_t)v;
	}
	if ((uint64_t)want != got) {
		char ann[ZDBG_SYM_NAME_MAX + ZDBG_SYM_MODULE_MAX + 48];
		char gnn[ZDBG_SYM_NAME_MAX + ZDBG_SYM_MODULE_MAX + 48];
		annot_addr(d, (zaddr_t)want, ann, sizeof(ann));
		annot_addr(d, (zaddr_t)got, gnn, sizeof(gnn));
		return check_fail(
		    "%s expected %016llx%s, got %016llx%s",
		    name, (unsigned long long)want, ann,
		    (unsigned long long)got, gnn);
	}
	return 0;
}

static int
check_mem(struct zdbg *d, char **argv, int argc)
{
	uint8_t pat[ZDBG_SEARCH_MAX_PATTERN];
	uint8_t got[ZDBG_SEARCH_MAX_PATTERN];
	size_t patlen = 0;
	zaddr_t addr;
	int i = 1; /* argv[0] is "mem" */
	int rc;
	size_t k;

	if (!have_target(d))
		return check_fail("no target");
	if (!target_stopped(d))
		return check_fail("target not stopped");
	if (i >= argc)
		return check_fail("usage: check mem ADDR PATTERN");
	if (eval_addr(d, argv[i], &addr) < 0)
		return check_fail("bad address: %s", argv[i]);
	i++;
	if (i >= argc)
		return check_fail("usage: check mem ADDR PATTERN");

	rc = parse_pattern_selector(d, argv, argc, &i, pat, sizeof(pat),
	    &patlen);
	if (rc < 0)
		return -1;
	if (rc == 0) {
		/* Raw byte tokens: join remaining argv into a buffer
		 * and let zmem_parse_bytes handle the same syntax as
		 * `s addr len bytes...`. */
		char tmp[ZDBG_SEARCH_MAX_PATTERN * 4];
		size_t tlen = 0;
		int j;
		tmp[0] = 0;
		for (j = i; j < argc; j++) {
			size_t need = strlen(argv[j]) + 2;
			if (tlen + need >= sizeof(tmp))
				return check_fail("pattern too long");
			if (tlen)
				tmp[tlen++] = ' ';
			memcpy(tmp + tlen, argv[j], strlen(argv[j]));
			tlen += strlen(argv[j]);
			tmp[tlen] = 0;
		}
		if (zmem_parse_bytes(tmp, pat, sizeof(pat), &patlen) < 0
		    || patlen == 0)
			return check_fail("bad bytes");
	}

	if (patlen > sizeof(got))
		return check_fail("pattern too long");
	if (ztarget_read(&d->target, addr, got, patlen) < 0)
		return check_fail(
		    "cannot read memory at %016llx",
		    (unsigned long long)addr);
	for (k = 0; k < patlen; k++) {
		if (got[k] != pat[k])
			return check_fail(
			    "memory %016llx differs at +0x%x: "
			    "expected %02x got %02x",
			    (unsigned long long)addr, (unsigned int)k,
			    (unsigned int)pat[k],
			    (unsigned int)got[k]);
	}
	return 0;
}

static int
check_symbol(struct zdbg *d, const char *name)
{
	zaddr_t out;
	int rc;

	if (name == NULL || *name == 0)
		return check_fail("usage: check symbol NAME");
	rc = check_resolve_symbol_strict(d, name, &out);
	if (rc == 0)
		return 0;
	if (rc == -3)
		return check_fail("symbol name is numeric: %s", name);
	if (rc == -2)
		return check_fail("symbol ambiguous: %s", name);
	return check_fail("symbol not found: %s", name);
}

static int
check_nosymbol(struct zdbg *d, const char *name)
{
	zaddr_t out;
	int rc;

	if (name == NULL || *name == 0)
		return check_fail("usage: check nosymbol NAME");
	if (check_token_is_numeric(name))
		return check_fail("symbol name is numeric: %s", name);
	rc = check_resolve_symbol_strict(d, name, &out);
	if (rc == 0)
		return check_fail("symbol resolved unexpectedly: %s", name);
	return 0;
}

static int
check_map(struct zdbg *d, const char *expr)
{
	zaddr_t addr;
	const struct zmap *m = NULL;

	if (expr == NULL || *expr == 0)
		return check_fail("usage: check map EXPR");
	if (eval_addr(d, expr, &addr) < 0)
		return check_fail("bad expression: %s", expr);
	if (d->have_regions)
		m = zmaps_find_by_addr(&d->regions, addr);
	if (m == NULL && d->have_maps)
		m = zmaps_find_by_addr(&d->maps, addr);
	if (m == NULL)
		return check_fail(
		    "address %016llx is not in any known map/region",
		    (unsigned long long)addr);
	return 0;
}

static int
check_patch_state(struct zdbg *d, const char *idtok, const char *state)
{
	uint64_t v;
	const struct zpatch *p = NULL;

	if (zexpr_eval(idtok, NULL, &v) < 0)
		return check_fail("bad patch id: %s", idtok);
	if (zpatch_get(&d->patches, (int)v, &p) < 0 || p == NULL)
		return check_fail("no patch %d", (int)v);
	if (strcmp(state, "applied") == 0) {
		if (p->state != ZPATCH_APPLIED)
			return check_fail("patch %d not applied",
			    (int)v);
		return 0;
	}
	if (strcmp(state, "reverted") == 0) {
		if (p->state != ZPATCH_REVERTED)
			return check_fail("patch %d not reverted",
			    (int)v);
		return 0;
	}
	return check_fail("unknown patch state: %s", state);
}

static int
check_bp_state(struct zdbg *d, const char *idtok, const char *state)
{
	uint64_t v;
	int id;
	struct zbp *b;

	if (zexpr_eval(idtok, NULL, &v) < 0)
		return check_fail("bad bp id: %s", idtok);
	id = (int)v;
	if (id < 0 || id >= ZDBG_MAX_BREAKPOINTS)
		return check_fail("bp id out of range: %d", id);
	b = &d->bps.bp[id];
	if (b->state == ZBP_EMPTY)
		return check_fail("no breakpoint %d", id);
	if (strcmp(state, "enabled") == 0) {
		if (b->state != ZBP_ENABLED)
			return check_fail("bp %d not enabled", id);
		return 0;
	}
	if (strcmp(state, "disabled") == 0) {
		if (b->state != ZBP_DISABLED)
			return check_fail("bp %d not disabled", id);
		return 0;
	}
	if (strcmp(state, "installed") == 0) {
		if (!b->installed)
			return check_fail("bp %d not installed", id);
		return 0;
	}
	if (strcmp(state, "removed") == 0) {
		if (b->installed)
			return check_fail("bp %d still installed", id);
		return 0;
	}
	return check_fail("unknown bp state: %s", state);
}

/*
 * Common filter-state assertions for both software breakpoints
 * and hardware breakpoints/watchpoints:
 *
 *   hits N      filter.hits equals N exactly
 *   ignore N    filter.ignore equals N exactly
 *   cond none   condition is not set
 *   cond TEXT   condition string equals TEXT verbatim
 */
static int
check_filter_state(const char *label, int id, const struct zstop_filter *f,
    const char *kind, const char *arg)
{
	uint64_t want;

	if (kind == NULL)
		return check_fail("usage: check %s %d hits|ignore|cond ...",
		    label, id);
	if (strcmp(kind, "hits") == 0) {
		if (arg == NULL || zexpr_eval(arg, NULL, &want) < 0)
			return check_fail(
			    "usage: check %s %d hits VALUE",
			    label, id);
		if (f->hits != want)
			return check_fail(
			    "%s %d hits expected %llu, got %llu",
			    label, id, (unsigned long long)want,
			    (unsigned long long)f->hits);
		return 0;
	}
	if (strcmp(kind, "ignore") == 0) {
		if (arg == NULL || zexpr_eval(arg, NULL, &want) < 0)
			return check_fail(
			    "usage: check %s %d ignore VALUE",
			    label, id);
		if (f->ignore != want)
			return check_fail(
			    "%s %d ignore expected %llu, got %llu",
			    label, id, (unsigned long long)want,
			    (unsigned long long)f->ignore);
		return 0;
	}
	if (strcmp(kind, "cond") == 0) {
		if (arg == NULL)
			return check_fail(
			    "usage: check %s %d cond none|EXPR",
			    label, id);
		if (strcmp(arg, "none") == 0) {
			if (f->has_cond)
				return check_fail(
				    "%s %d condition expected none, got"
				    " \"%s\"", label, id, f->cond);
			return 0;
		}
		if (!f->has_cond)
			return check_fail(
			    "%s %d condition expected \"%s\", got none",
			    label, id, arg);
		if (strcmp(f->cond, arg) != 0)
			return check_fail(
			    "%s %d condition expected \"%s\", got \"%s\"",
			    label, id, arg, f->cond);
		return 0;
	}
	return -2; /* unknown kind: caller may try state strings */
}

/*
 * Concatenate argv[start..end) into `out` separated by single
 * spaces, without quoting.  Used for `check bp/hwbp cond TEXT`
 * which allows whitespace inside the condition text.  Returns
 * 0 on success, -1 if the joined result does not fit in `cap`.
 */
static int
join_args(char *out, size_t cap, char **argv, int start, int end)
{
	int i;
	size_t len = 0;
	size_t need;

	if (out == NULL || cap == 0)
		return -1;
	out[0] = 0;
	for (i = start; i < end; i++) {
		need = strlen(argv[i]);
		if (i > start) {
			if (len + 1 >= cap)
				return -1;
			out[len++] = ' ';
		}
		if (len + need >= cap)
			return -1;
		memcpy(out + len, argv[i], need);
		len += need;
	}
	out[len] = 0;
	return 0;
}

/*
 * Shared `actions COUNT` / `silent yes|no` assertions for both
 * software and hardware breakpoint slots.  Returns 0 on match,
 * a check_fail() result on mismatch, and -2 when `kind` is not
 * an action-related keyword so the caller can try other forms.
 */
static int
check_actions_state(const char *label, int id,
    const struct zaction_list *a, const char *kind, const char *arg)
{
	uint64_t want;

	if (kind == NULL)
		return -2;
	if (strcmp(kind, "actions") == 0) {
		if (arg == NULL || zexpr_eval(arg, NULL, &want) < 0)
			return check_fail(
			    "usage: check %s %d actions COUNT",
			    label, id);
		if ((uint64_t)a->count != want)
			return check_fail(
			    "%s %d actions expected %llu, got %d",
			    label, id, (unsigned long long)want, a->count);
		return 0;
	}
	if (strcmp(kind, "silent") == 0) {
		int want_silent;
		if (arg == NULL)
			return check_fail(
			    "usage: check %s %d silent yes|no",
			    label, id);
		if (strcmp(arg, "yes") == 0 || strcmp(arg, "on") == 0)
			want_silent = 1;
		else if (strcmp(arg, "no") == 0 || strcmp(arg, "off") == 0)
			want_silent = 0;
		else
			return check_fail(
			    "usage: check %s %d silent yes|no",
			    label, id);
		if ((a->silent ? 1 : 0) != want_silent)
			return check_fail(
			    "%s %d silent expected %s, got %s",
			    label, id,
			    want_silent ? "yes" : "no",
			    a->silent ? "yes" : "no");
		return 0;
	}
	return -2;
}

static int
check_bp(struct zdbg *d, char **argv, int argc)
{
	uint64_t v;
	int id;
	struct zbp *b;
	int rc;
	char joined[ZDBG_FILTER_EXPR_MAX];
	const char *cond_arg;

	/* argv[0]="bp", argv[1]=ID, argv[2]=KIND, argv[3..]=arg */
	if (argc < 3)
		return check_fail(
		    "usage: check bp ID enabled|disabled|installed|"
		    "removed|hits N|ignore N|cond ...");
	if (zexpr_eval(argv[1], NULL, &v) < 0)
		return check_fail("bad bp id: %s", argv[1]);
	id = (int)v;
	if (id < 0 || id >= ZDBG_MAX_BREAKPOINTS)
		return check_fail("bp id out of range: %d", id);
	b = &d->bps.bp[id];
	if (b->state == ZBP_EMPTY)
		return check_fail("no breakpoint %d", id);

	/* `cond TEXT` permits whitespace inside TEXT: re-join argv[3..] */
	cond_arg = NULL;
	if (argc >= 4) {
		if (join_args(joined, sizeof(joined), argv, 3, argc) < 0)
			return check_fail("bp %d condition arg too long",
			    id);
		cond_arg = joined;
	}
	rc = check_filter_state("bp", id, &b->filter, argv[2], cond_arg);
	if (rc != -2)
		return rc;
	rc = check_actions_state("bp", id, &b->actions, argv[2],
	    argc >= 4 ? argv[3] : NULL);
	if (rc != -2)
		return rc;
	return check_bp_state(d, argv[1], argv[2]);
}

static int
check_hwbp_state(struct zdbg *d, const char *idtok, const char *state)
{
	uint64_t v;
	int id;
	struct zhwbp *b;

	if (zexpr_eval(idtok, NULL, &v) < 0)
		return check_fail("bad hwbp id: %s", idtok);
	id = (int)v;
	if (id < 0 || id >= ZDBG_MAX_HWBP)
		return check_fail("hwbp id out of range: %d", id);
	b = &d->hwbps.bp[id];
	if (b->state == ZHWBP_EMPTY)
		return check_fail("no hwbp %d", id);
	if (strcmp(state, "enabled") == 0) {
		if (b->state != ZHWBP_ENABLED)
			return check_fail("hwbp %d not enabled", id);
		return 0;
	}
	if (strcmp(state, "disabled") == 0) {
		if (b->state != ZHWBP_DISABLED)
			return check_fail("hwbp %d not disabled", id);
		return 0;
	}
	return check_fail("unknown hwbp state: %s", state);
}

static int
check_hwbp(struct zdbg *d, char **argv, int argc)
{
	uint64_t v;
	int id;
	struct zhwbp *b;
	int rc;
	char joined[ZDBG_FILTER_EXPR_MAX];
	const char *cond_arg;

	if (argc < 3)
		return check_fail(
		    "usage: check hwbp ID enabled|disabled|"
		    "hits N|ignore N|cond ...");
	if (zexpr_eval(argv[1], NULL, &v) < 0)
		return check_fail("bad hwbp id: %s", argv[1]);
	id = (int)v;
	if (id < 0 || id >= ZDBG_MAX_HWBP)
		return check_fail("hwbp id out of range: %d", id);
	b = &d->hwbps.bp[id];
	if (b->state == ZHWBP_EMPTY)
		return check_fail("no hwbp %d", id);
	cond_arg = NULL;
	if (argc >= 4) {
		if (join_args(joined, sizeof(joined), argv, 3, argc) < 0)
			return check_fail("hwbp %d condition arg too long",
			    id);
		cond_arg = joined;
	}
	rc = check_filter_state("hwbp", id, &b->filter, argv[2], cond_arg);
	if (rc != -2)
		return rc;
	rc = check_actions_state("hwbp", id, &b->actions, argv[2],
	    argc >= 4 ? argv[3] : NULL);
	if (rc != -2)
		return rc;
	return check_hwbp_state(d, argv[1], argv[2]);
}

/*
 * `check file PATH exists` returns 0 if PATH can be opened.
 * `check file PATH size LEN` additionally requires the file to
 * be exactly LEN bytes long.  fopen/fseek/ftell are sufficient
 * for the small artefacts these checks are aimed at; anything
 * larger than `long` reports a clean failure.
 */
static int
check_file(const char *path, const char *kind, const char *arg)
{
	FILE *fp;

	if (path == NULL || *path == 0 || kind == NULL)
		return check_fail("usage: check file PATH exists|size LEN");

	if (strcmp(kind, "exists") == 0) {
		fp = fopen(path, "rb");
		if (fp == NULL)
			return check_fail("file does not exist: %s", path);
		fclose(fp);
		return 0;
	}
	if (strcmp(kind, "size") == 0) {
		uint64_t want;
		long sz;
		if (arg == NULL ||
		    zexpr_eval(arg, NULL, &want) < 0)
			return check_fail(
			    "usage: check file PATH size LEN");
		fp = fopen(path, "rb");
		if (fp == NULL)
			return check_fail("file does not exist: %s", path);
		if (fseek(fp, 0, SEEK_END) != 0) {
			fclose(fp);
			return check_fail("cannot seek: %s", path);
		}
		sz = ftell(fp);
		fclose(fp);
		if (sz < 0)
			return check_fail("cannot size: %s", path);
		if ((uint64_t)sz != want)
			return check_fail(
			    "file %s size expected %llu, got %llu",
			    path, (unsigned long long)want,
			    (unsigned long long)sz);
		return 0;
	}
	return check_fail("unknown file check: %s", kind);
}

static int
cmd_check(struct zdbg *d, struct toks *t)
{
	struct cmd_qargs a;
	const char *line;
	const char *sub;
	int argc;
	char **argv;

	(void)t;
	/* Re-parse from the original line so quoted arguments
	 * (paths, strings) survive intact.  rest_from(t->orig, 1)
	 * starts after the command word. */
	line = rest_from(t->orig, 1);
	while (*line == ' ' || *line == '\t')
		line++;
	if (cmd_qsplit(line, &a) < 0)
		return check_fail("argument list too long");
	if (a.n < 1)
		return check_fail(
		    "usage: %s SUBCOMMAND ... (try `?`)", check_word);
	argc = a.n;
	argv = a.v;
	sub = argv[0];

	if (strcmp(sub, "target") == 0)
		return check_target(d);
	if (strcmp(sub, "stopped") == 0)
		return check_stopped(d);
	if (strcmp(sub, "running") == 0)
		return check_running(d);
	if (strcmp(sub, "exited") == 0) {
		if (argc == 1)
			return check_exited(d, 0, 0);
		{
			uint64_t v;
			if (zexpr_eval(argv[1], NULL, &v) < 0)
				return check_fail("bad code: %s", argv[1]);
			return check_exited(d, 1, (int)v);
		}
	}
	if (strcmp(sub, "stop") == 0) {
		if (argc < 2)
			return check_fail("usage: %s stop REASON",
			    check_word);
		return check_stop(d, argv[1]);
	}
	if (strcmp(sub, "thread") == 0)
		return check_thread(d, argc >= 2 ? argv[1] : NULL);
	if (strcmp(sub, "reg") == 0) {
		if (argc < 3)
			return check_fail(
			    "usage: %s reg NAME VALUE", check_word);
		return check_reg(d, argv[1], argv[2]);
	}
	if (strcmp(sub, "rip") == 0) {
		if (argc < 2)
			return check_fail("usage: %s rip EXPR",
			    check_word);
		return check_reg(d, "rip", argv[1]);
	}
	if (strcmp(sub, "mem") == 0)
		return check_mem(d, argv, argc);
	if (strcmp(sub, "symbol") == 0 || strcmp(sub, "sym") == 0) {
		if (argc < 2)
			return check_fail("usage: %s symbol NAME",
			    check_word);
		return check_symbol(d, argv[1]);
	}
	if (strcmp(sub, "nosymbol") == 0 || strcmp(sub, "nosym") == 0) {
		if (argc < 2)
			return check_fail("usage: %s nosymbol NAME",
			    check_word);
		return check_nosymbol(d, argv[1]);
	}
	if (strcmp(sub, "map") == 0) {
		if (argc < 2)
			return check_fail("usage: %s map EXPR",
			    check_word);
		return check_map(d, argv[1]);
	}
	if (strcmp(sub, "patch") == 0) {
		if (argc < 3)
			return check_fail(
			    "usage: %s patch ID applied|reverted",
			    check_word);
		return check_patch_state(d, argv[1], argv[2]);
	}
	if (strcmp(sub, "bp") == 0) {
		if (argc < 3)
			return check_fail(
			    "usage: %s bp ID enabled|disabled|"
			    "installed|removed|hits N|ignore N|cond ...",
			    check_word);
		return check_bp(d, argv, argc);
	}
	if (strcmp(sub, "hwbp") == 0) {
		if (argc < 3)
			return check_fail(
			    "usage: %s hwbp ID enabled|disabled|"
			    "hits N|ignore N|cond ...", check_word);
		return check_hwbp(d, argv, argc);
	}
	if (strcmp(sub, "file") == 0) {
		if (argc < 3)
			return check_fail(
			    "usage: %s file PATH exists|size LEN",
			    check_word);
		return check_file(argv[1], argv[2],
		    argc >= 4 ? argv[3] : NULL);
	}
	return check_fail("unknown subcommand: %s", sub);
}

/* --- top-level dispatch --------------------------------------- */

void
zdbg_init(struct zdbg *d)
{
	if (d == NULL)
		return;
	memset(d, 0, sizeof(*d));
	ztarget_init(&d->target);
	zbp_table_init(&d->bps);
	zhwbp_table_init(&d->hwbps);
	zregs_clear(&d->regs);
	zmaps_init(&d->maps);
	zmaps_init(&d->regions);
	zsyms_init(&d->syms);
	zsig_table_init(&d->sigs);
	zexc_table_init(&d->excs);
	zpatch_table_init(&d->patches);
	d->dump_addr = 0;
	d->asm_addr = 0;
	d->have_regs = 0;
	d->have_maps = 0;
	d->have_regions = 0;
	d->have_syms = 0;
	d->stopped_bp = -1;
	d->stopped_hwbp = -1;
	d->have_last_stop = 0;
	d->last_stop_hwbp = -1;
	d->last_stop_is_watch = 0;
	d->quit_requested = 0;
	d->had_error = 0;
	d->last_status = 0;
	d->source_depth = 0;
	d->verbose = 0;
	d->quiet = 0;
}

void
zdbg_fini(struct zdbg *d)
{
	if (d == NULL)
		return;
	ztarget_fini(&d->target);
}

int
zcmd_exec(struct zdbg *d, const char *line)
{
	struct toks t;
	const char *p;
	char mn[16];

	if (d == NULL || line == NULL)
		return -1;

	p = line;
	while (*p == ' ' || *p == '\t')
		p++;
	if (*p == 0 || *p == ';' || *p == '#')
		return 0;

	tokenize(p, &t);
	if (t.n == 0)
		return 0;

	{
		size_t i, n = strlen(t.v[0]);
		if (n >= sizeof(mn))
			n = sizeof(mn) - 1;
		for (i = 0; i < n; i++)
			mn[i] = t.v[0][i];
		mn[n] = 0;
		to_lower(mn);
		t.v[0] = mn;
	}

	if (strcmp(mn, "?") == 0 || strcmp(mn, "help") == 0) {
		print_help();
		return 0;
	}
	if (strcmp(mn, "q") == 0 || strcmp(mn, "quit") == 0 ||
	    strcmp(mn, "exit") == 0) {
		d->quit_requested = 1;
		return RC_QUIT;
	}
	if (strcmp(mn, "source") == 0 || strcmp(mn, ".") == 0)
		return cmd_source(d, &t);
	if (strcmp(mn, "r") == 0)
		return cmd_r(d, &t);
	if (strcmp(mn, "d") == 0 || strcmp(mn, "x") == 0)
		return cmd_d(d, &t);
	if (strcmp(mn, "e") == 0)
		return cmd_e(d, &t);
	if (strcmp(mn, "f") == 0)
		return cmd_f(d, &t);
	if (strcmp(mn, "s") == 0)
		return cmd_s(d, &t);
	if (strcmp(mn, "c") == 0)
		return cmd_c(d, &t);
	if (strcmp(mn, "m") == 0)
		return cmd_m(d, &t);
	if (strcmp(mn, "wf") == 0)
		return cmd_wf(d, &t);
	if (strcmp(mn, "rf") == 0)
		return cmd_rf(d, &t);
	if (strcmp(mn, "u") == 0)
		return cmd_u(d, &t);
	if (strcmp(mn, "a") == 0)
		return cmd_a(d, &t);
	if (strcmp(mn, "pa") == 0)
		return cmd_pa(d, &t);
	if (strcmp(mn, "ij") == 0)
		return cmd_ij(d, &t);
	if (strcmp(mn, "pl") == 0)
		return cmd_pl(d, &t);
	if (strcmp(mn, "pu") == 0)
		return cmd_pu(d, &t);
	if (strcmp(mn, "pr") == 0)
		return cmd_pr(d, &t);
	if (strcmp(mn, "pf") == 0)
		return cmd_pf(d, &t);
	if (strcmp(mn, "ps") == 0)
		return cmd_ps(d, &t);
	if (strcmp(mn, "pw") == 0)
		return cmd_pw(d, &t);
	if (strcmp(mn, "b") == 0)
		return cmd_b(d, &t);
	if (strcmp(mn, "bc") == 0)
		return cmd_bc(d, &t);
	if (strcmp(mn, "bd") == 0)
		return cmd_bd(d, &t);
	if (strcmp(mn, "be") == 0)
		return cmd_be(d, &t);
	if (strcmp(mn, "hb") == 0)
		return cmd_hb(d, &t);
	if (strcmp(mn, "hw") == 0)
		return cmd_hw(d, &t);
	if (strcmp(mn, "hl") == 0)
		return cmd_hl(d, &t);
	if (strcmp(mn, "hc") == 0)
		return cmd_hc(d, &t);
	if (strcmp(mn, "hd") == 0)
		return cmd_hd(d, &t);
	if (strcmp(mn, "he") == 0)
		return cmd_he(d, &t);
	if (strcmp(mn, "cond") == 0)
		return cmd_cond(d, &t);
	if (strcmp(mn, "ignore") == 0)
		return cmd_ignore(d, &t);
	if (strcmp(mn, "hits") == 0)
		return cmd_hits(d, &t);
	if (strcmp(mn, "actions") == 0 || strcmp(mn, "commands") == 0) {
		if (d->in_action) {
			printf("action rejected: command not allowed in"
			    " breakpoint action list: %s\n", mn);
			return -1;
		}
		return cmd_actions(d, &t);
	}
	if (strcmp(mn, "trace") == 0) {
		if (d->in_action) {
			printf("action rejected: command not allowed in"
			    " breakpoint action list: %s\n", mn);
			return -1;
		}
		return cmd_trace(d, &t);
	}
	if (strcmp(mn, "printf") == 0)
		return cmd_printf(d, &t);
	if (strcmp(mn, "g") == 0)
		return cmd_g(d, &t);
	if (strcmp(mn, "t") == 0)
		return cmd_t(d, &t);
	if (strcmp(mn, "p") == 0)
		return cmd_p(d, &t);
	if (strcmp(mn, "l") == 0)
		return cmd_l(d, &t);
	if (strcmp(mn, "la") == 0)
		return cmd_la(d, &t);
	if (strcmp(mn, "ld") == 0)
		return cmd_ld(d, &t);
	if (strcmp(mn, "k") == 0)
		return cmd_k(d, &t);
	if (strcmp(mn, "lm") == 0)
		return cmd_lm(d, &t);
	if (strcmp(mn, "sym") == 0)
		return cmd_sym(d, &t);
	if (strcmp(mn, "addr") == 0)
		return cmd_addr(d, &t);
	if (strcmp(mn, "bt") == 0)
		return cmd_bt(d, &t);
	if (strcmp(mn, "th") == 0)
		return cmd_th(d, &t);
	if (strcmp(mn, "sig") == 0)
		return cmd_sig(d, &t);
	if (strcmp(mn, "ex") == 0)
		return cmd_ex(d, &t);
	if (strcmp(mn, "handle") == 0)
		return cmd_handle(d, &t);
	if (strcmp(mn, "check") == 0) {
		check_word = "check";
		return cmd_check(d, &t);
	}
	if (strcmp(mn, "assert") == 0) {
		int rc;
		check_word = "assert";
		rc = cmd_check(d, &t);
		check_word = "check";
		return rc;
	}
	if (strcmp(mn, "expect") == 0) {
		int rc;
		check_word = "expect";
		rc = cmd_check(d, &t);
		check_word = "check";
		return rc;
	}

	printf("unknown command: %s (try ?)\n", mn);
	return -1;
}
