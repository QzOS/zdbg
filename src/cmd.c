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
#include "zdbg_mem.h"
#include "zdbg_regs.h"
#include "zdbg_target.h"
#include "zdbg_tinyasm.h"
#include "zdbg_tinydis.h"

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
	    "  r [reg [value]]      show/set cached register value\n"
	    "  d [addr [len]]       dump memory\n"
	    "  x [addr [len]]       alias for d\n"
	    "  e addr bytes...      write bytes\n"
	    "  f addr len bytes...  fill memory\n"
	    "  u [addr [count]]     tiny unassemble\n"
	    "  a [addr]             interactive tiny assemble\n"
	    "  pa addr len insn     patch instruction + NOP fill\n"
	    "  ij addr              invert jz/jnz at addr\n"
	    "  b [addr]             list/set breakpoint\n"
	    "  bc n|*               clear breakpoint\n"
	    "  bd n                 disable breakpoint\n"
	    "  be n                 enable breakpoint\n"
	    "  g                    continue\n"
	    "  t                    single step\n");
}

static int
have_target(struct zdbg *d)
{
	return d->target.state != ZTARGET_EMPTY;
}

/* --- r --------------------------------------------------------- */
static int
cmd_r(struct zdbg *d, struct toks *t)
{
	if (t->n == 1) {
		zregs_print(&d->regs);
		return 0;
	}
	if (t->n == 2) {
		uint64_t v = 0;
		if (zregs_get_by_name(&d->regs, t->v[1], &v) < 0) {
			printf("unknown register: %s\n", t->v[1]);
			return -1;
		}
		printf("%s = %016llx\n", t->v[1], (unsigned long long)v);
		return 0;
	}
	if (t->n >= 3) {
		uint64_t v = 0;
		if (zexpr_eval(t->v[2], &d->regs, &v) < 0) {
			printf("bad value\n");
			return -1;
		}
		if (zregs_set_by_name(&d->regs, t->v[1], v) < 0) {
			printf("unknown register: %s\n", t->v[1]);
			return -1;
		}
		d->have_regs = 1;
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
		if (zexpr_eval(t->v[1], &d->regs, &addr) < 0) {
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
	if (zexpr_eval(t->v[1], &d->regs, &addr) < 0) {
		printf("bad address\n");
		return -1;
	}
	if (zmem_parse_bytes(rest_from(t->orig, 2), buf, sizeof(buf),
	    &blen) < 0) {
		printf("bad bytes\n");
		return -1;
	}
	if (!have_target(d) ||
	    ztarget_write(&d->target, addr, buf, blen) < 0) {
		printf("target operation not available in this backend yet\n");
		return -1;
	}
	return 0;
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
	if (zexpr_eval(t->v[1], &d->regs, &addr) < 0) {
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
	if (!have_target(d) ||
	    ztarget_write(&d->target, addr, buf, (size_t)len) < 0) {
		printf("target operation not available in this backend yet\n");
		return -1;
	}
	return 0;
}

/* --- u --------------------------------------------------------- */
static int
cmd_u(struct zdbg *d, struct toks *t)
{
	zaddr_t addr = d->asm_addr;
	int count = 8;
	uint8_t buf[128];
	int i;

	if (t->n >= 2) {
		if (zexpr_eval(t->v[1], &d->regs, &addr) < 0) {
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
			ztinydis_print(&dis);
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
		if (zexpr_eval(t->v[1], &d->regs, &addr) < 0) {
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
			if (ztarget_write(&d->target, addr, enc.code,
			    enc.len) < 0) {
				printf("write failed (backend unavailable)\n");
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
	if (zexpr_eval(t->v[1], &d->regs, &addr) < 0) {
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
	if (have_target(d)) {
		if (ztarget_write(&d->target, addr, buf, out_len) < 0)
			printf("target operation not available in this "
			    "backend yet\n");
	}
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
	if (zexpr_eval(t->v[1], &d->regs, &addr) < 0) {
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
	if (ztarget_write(&d->target, addr, buf, used) < 0) {
		printf("write failed\n");
		return -1;
	}
	return 0;
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
	if (zexpr_eval(t->v[1], &d->regs, &addr) < 0) {
		printf("bad address\n");
		return -1;
	}
	id = zbp_alloc(&d->bps, addr, 0);
	if (id < 0) {
		printf("breakpoint table full\n");
		return -1;
	}
	printf("bp %d at %016llx\n", id, (unsigned long long)addr);
	if (have_target(d))
		(void)zbp_enable(&d->target, &d->bps, id);
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
		return 0;
	}
	if (parse_bp_id(t->v[1], &id) < 0) {
		printf("bad id\n");
		return -1;
	}
	return zbp_clear(&d->target, &d->bps, id);
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
	return 0;
}

static int
cmd_be(struct zdbg *d, struct toks *t)
{
	int id;
	if (t->n < 2 || parse_bp_id(t->v[1], &id) < 0) {
		printf("usage: be n\n");
		return -1;
	}
	if (zbp_enable(&d->target, &d->bps, id) < 0) {
		printf("target operation not available in this backend yet\n");
		return -1;
	}
	return 0;
}

/* --- g / t ----------------------------------------------------- */
static int
cmd_g(struct zdbg *d, struct toks *t)
{
	(void)t;
	if (ztarget_continue(&d->target) < 0) {
		printf("target operation not available in this backend yet\n");
		return -1;
	}
	return 0;
}

static int
cmd_t(struct zdbg *d, struct toks *t)
{
	(void)t;
	if (ztarget_singlestep(&d->target) < 0) {
		printf("target operation not available in this backend yet\n");
		return -1;
	}
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
	zregs_clear(&d->regs);
	d->dump_addr = 0;
	d->asm_addr = 0;
	d->have_regs = 0;
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
	if (strcmp(mn, "b") == 0)
		return cmd_b(d, &t);
	if (strcmp(mn, "bc") == 0)
		return cmd_bc(d, &t);
	if (strcmp(mn, "bd") == 0)
		return cmd_bd(d, &t);
	if (strcmp(mn, "be") == 0)
		return cmd_be(d, &t);
	if (strcmp(mn, "g") == 0)
		return cmd_g(d, &t);
	if (strcmp(mn, "t") == 0)
		return cmd_t(d, &t);

	printf("unknown command: %s (try ?)\n", mn);
	return -1;
}
