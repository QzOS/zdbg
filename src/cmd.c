/*
 * cmd.c - command parser and dispatcher.
 *
 * The REPL (repl.c) reads a line and calls zcmd_exec() with it.
 * Every individual command handler lives here, keeping the
 * parsing layer isolated from both the REPL and the backends.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "zdbg.h"
#include "zdbg_cmd.h"
#include "zdbg_expr.h"
#include "zdbg_hwbp.h"
#include "zdbg_maps.h"
#include "zdbg_mem.h"
#include "zdbg_regs.h"
#include "zdbg_signal.h"
#include "zdbg_symbols.h"
#include "zdbg_target.h"
#include "zdbg_tinyasm.h"
#include "zdbg_tinydis.h"
#include "zdbg_patch.h"

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
	    "  lm [addr]            list maps or show map at addr\n"
	    "  sym [filter|-r]      list/search/refresh ELF symbols\n"
	    "  addr expr            show address, nearest symbol, mapping\n"
	    "  bt [count]           frame-pointer backtrace\n"
	    "  g                    continue\n"
	    "  t                    single step\n"
	    "  p                    proceed / step over direct call\n"
	    "  th [tid|index]       list/select traced thread\n"
	    "  sig [-l|0|name|num]  show/list/clear/set pending signal\n"
	    "  handle [sig [opts]]  show/set signal stop/pass/print policy\n");
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
	 */
	if (st->reason == ZSTOP_BREAKPOINT && d != NULL &&
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
	case ZSTOP_EXCEPTION:
		printf("stopped: %sexception rip=%016llx%s\n",
		    tp, (unsigned long long)st->addr, ann);
		return;
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
 * Forget the cached memory map.  Used on detach/kill/new launch.
 */
static void
clear_maps(struct zdbg *d)
{
	d->have_maps = 0;
	d->maps.count = 0;
	d->maps.truncated = 0;
	d->maps.main_hint[0] = 0;
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
		const char *s;
		const char *kname;

		if (b->state == ZHWBP_EMPTY)
			continue;
		s = (b->state == ZHWBP_ENABLED) ? "enabled " : "disabled";
		kname = (b->kind == ZHWBP_EXEC) ? "exec     " :
		    (b->kind == ZHWBP_WRITE) ? "write    " : "readwrite";
		annot_addr(d, b->addr, ann, sizeof(ann));
		printf(" %d %s %s len=%d %016llx%s\n", i, s, kname, b->len,
		    (unsigned long long)b->addr, ann);
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

/* --- g / t ----------------------------------------------------- */

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
			return 0;
		}

		zstop_print(d, &st, bp_id);
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
static int
cmd_lm(struct zdbg *d, struct toks *t)
{
	zaddr_t addr;
	const struct zmap *m;

	if (!have_target(d)) {
		printf("no target\n");
		return -1;
	}
	refresh_maps(d);
	refresh_syms(d);
	if (!d->have_maps) {
		printf("could not read process maps\n");
		return -1;
	}
	if (t->n < 2) {
		zmaps_print(&d->maps);
		return 0;
	}
	if (eval_addr(d, t->v[1], &addr) < 0) {
		printf("bad address\n");
		return -1;
	}
	m = zmaps_find_by_addr(&d->maps, addr);
	if (m == NULL) {
		printf("%016llx: no mapping\n", (unsigned long long)addr);
		return -1;
	}
	zmaps_print_one((int)(m - d->maps.maps), m);
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
	if (d->have_maps)
		m = zmaps_find_by_addr(&d->maps, addr);
	printf("%016llx%s%s%s\n", (unsigned long long)addr, ann,
	    m != NULL ? " " : "",
	    m != NULL ? m->name : "");
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
	const struct zsig_policy *p;
	int set_stop = 0, set_pass = 0, set_print = 0;
	int stop = 0, pass = 0, print = 0;
	int i;

	if (t->n == 1) {
		zsig_print_table(&d->sigs);
		return 0;
	}
	if (zsig_parse(t->v[1], &sig) < 0 || sig == 0) {
		printf("unknown signal: %s\n", t->v[1]);
		return -1;
	}
	if (t->n == 2) {
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
	if (p->has_file)
		printf(" file=%s+0x%llx", p->file,
		    (unsigned long long)p->file_off);
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
		printf("patch %d has no file backing\n", id);
		return 0;
	}
	annot_addr(d, p->addr, ann, sizeof(ann));
	printf("patch %d:\n", id);
	printf("  va:       %016llx%s\n",
	    (unsigned long long)p->addr, ann);
	printf("  len:      %zu\n", p->len);
	printf("  file:     %s\n", p->file);
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

static int
cmd_pw(struct zdbg *d, struct toks *t)
{
	int id;
	const struct zpatch *p;
	int i;
	int nok = 0;
	int nfail = 0;

	if (t->n < 2) {
		printf("usage: pw id|*\n");
		return -1;
	}
	printf("warning: writing mapped file bytes on disk; no ELF "
	    "metadata is updated\n");
	if (strcmp(t->v[1], "*") == 0) {
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
	if (write_patch_to_file(p) < 0)
		return -1;
	printf("wrote patch %d to %s at file offset 0x%llx\n",
	    id, p->file, (unsigned long long)p->file_off);
	return 0;
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
	zsyms_init(&d->syms);
	zsig_table_init(&d->sigs);
	zpatch_table_init(&d->patches);
	d->dump_addr = 0;
	d->asm_addr = 0;
	d->have_regs = 0;
	d->have_maps = 0;
	d->have_syms = 0;
	d->stopped_bp = -1;
	d->stopped_hwbp = -1;
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
	    strcmp(mn, "exit") == 0)
		return RC_QUIT;
	if (strcmp(mn, "r") == 0)
		return cmd_r(d, &t);
	if (strcmp(mn, "d") == 0 || strcmp(mn, "x") == 0)
		return cmd_d(d, &t);
	if (strcmp(mn, "e") == 0)
		return cmd_e(d, &t);
	if (strcmp(mn, "f") == 0)
		return cmd_f(d, &t);
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
	if (strcmp(mn, "handle") == 0)
		return cmd_handle(d, &t);

	printf("unknown command: %s (try ?)\n", mn);
	return -1;
}
