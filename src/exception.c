/*
 * exception.c - Windows exception name/parse/policy subsystem.
 *
 * The name table below lists Windows Debug API exception codes
 * that zdbg recognizes.  The numeric values match <winnt.h> /
 * <ntstatus.h>; they are hard-coded here (rather than pulled
 * from <windows.h>) because the exception subsystem compiles on
 * every host, Windows or not.
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "zdbg_exception.h"

struct zexc_ent {
	uint32_t code;
	const char *name;	/* canonical Win32 macro name */
	const char *shortn;	/* short name without EXCEPTION_ prefix */
	const char *alias;	/* optional extra alias, NULL if none */
};

/*
 * Known Windows exception codes.  The short name is the macro
 * name with the leading "EXCEPTION_" (or "DBG_PRINTEXCEPTION_")
 * prefix stripped, lowercased in matches.  `alias` is a small
 * secondary name (e.g. "av" for access violation).
 */
static const struct zexc_ent zexc_names[] = {
	{ 0xc0000005, "EXCEPTION_ACCESS_VIOLATION",        "access_violation",         "av"     },
	{ 0xc000008c, "EXCEPTION_ARRAY_BOUNDS_EXCEEDED",   "array_bounds_exceeded",    NULL     },
	{ 0x80000003, "EXCEPTION_BREAKPOINT",              "breakpoint",               NULL     },
	{ 0x80000002, "EXCEPTION_DATATYPE_MISALIGNMENT",   "datatype_misalignment",    NULL     },
	{ 0xc000008d, "EXCEPTION_FLT_DENORMAL_OPERAND",    "flt_denormal_operand",     NULL     },
	{ 0xc000008e, "EXCEPTION_FLT_DIVIDE_BY_ZERO",      "flt_divide_by_zero",       NULL     },
	{ 0xc000008f, "EXCEPTION_FLT_INEXACT_RESULT",      "flt_inexact_result",       NULL     },
	{ 0xc0000090, "EXCEPTION_FLT_INVALID_OPERATION",   "flt_invalid_operation",    NULL     },
	{ 0xc0000091, "EXCEPTION_FLT_OVERFLOW",            "flt_overflow",             NULL     },
	{ 0xc0000092, "EXCEPTION_FLT_STACK_CHECK",         "flt_stack_check",          NULL     },
	{ 0xc0000093, "EXCEPTION_FLT_UNDERFLOW",           "flt_underflow",            NULL     },
	{ 0xc000001d, "EXCEPTION_ILLEGAL_INSTRUCTION",     "illegal_instruction",      NULL     },
	{ 0xc0000006, "EXCEPTION_IN_PAGE_ERROR",           "in_page_error",            NULL     },
	{ 0xc0000094, "EXCEPTION_INT_DIVIDE_BY_ZERO",      "int_divide_by_zero",       NULL     },
	{ 0xc0000095, "EXCEPTION_INT_OVERFLOW",            "int_overflow",             NULL     },
	{ 0xc0000026, "EXCEPTION_INVALID_DISPOSITION",     "invalid_disposition",      NULL     },
	{ 0xc0000025, "EXCEPTION_NONCONTINUABLE_EXCEPTION","noncontinuable_exception", NULL     },
	{ 0xc0000096, "EXCEPTION_PRIV_INSTRUCTION",        "priv_instruction",         NULL     },
	{ 0x80000004, "EXCEPTION_SINGLE_STEP",             "single_step",              NULL     },
	{ 0xc00000fd, "EXCEPTION_STACK_OVERFLOW",          "stack_overflow",           NULL     },
	{ 0x80000001, "EXCEPTION_GUARD_PAGE",              "guard_page",               NULL     },
	{ 0x40010006, "DBG_PRINTEXCEPTION_C",              "printexception_c",         NULL     },
	{ 0x4001000a, "DBG_PRINTEXCEPTION_WIDE_C",         "printexception_wide_c",    NULL     },
	{ 0xe06d7363, "MSVC_CPP_EXCEPTION",                "msvc_cpp",                 "cpp"    }
};

static const size_t zexc_names_n =
    sizeof(zexc_names) / sizeof(zexc_names[0]);

const char *
zexc_name(uint32_t code)
{
	size_t i;

	for (i = 0; i < zexc_names_n; i++) {
		if (zexc_names[i].code == code)
			return zexc_names[i].name;
	}
	return "EXCEPTION?";
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
parse_hex32(const char *s, uint32_t *vp)
{
	uint64_t v = 0;
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
		v = v * 16 + (uint64_t)d;
		if (v > 0xffffffffull)
			return -1;
		s++;
		any = 1;
	}
	if (!any)
		return -1;
	*vp = (uint32_t)v;
	return 0;
}

static int
parse_dec32(const char *s, uint32_t *vp)
{
	uint64_t v = 0;
	int any = 0;

	while (*s) {
		if (!isdigit((unsigned char)*s))
			return -1;
		v = v * 10 + (uint64_t)(*s - '0');
		if (v > 0xffffffffull)
			return -1;
		s++;
		any = 1;
	}
	if (!any)
		return -1;
	*vp = (uint32_t)v;
	return 0;
}

static int
is_all_hex(const char *s)
{
	int any = 0;
	while (*s) {
		unsigned char c = (unsigned char)*s;
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
		    (c >= 'A' && c <= 'F')))
			return 0;
		any = 1;
		s++;
	}
	return any;
}

static int
has_alpha(const char *s)
{
	while (*s) {
		unsigned char c = (unsigned char)*s;
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
			return 1;
		s++;
	}
	return 0;
}

int
zexc_parse(const char *s, uint32_t *codep)
{
	char buf[64];
	size_t n;
	size_t i;

	if (s == NULL || codep == NULL)
		return -1;
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

	/* "#NN" -> explicit decimal */
	if (buf[0] == '#')
		return parse_dec32(buf + 1, codep);

	/* "0xNN" -> hex */
	if (buf[0] == '0' && (buf[1] == 'x' || buf[1] == 'X'))
		return parse_hex32(buf + 2, codep);

	/* bare hex string like "c0000005" (contains a hex letter
	 * or is pure digits but looks like a full 32-bit code).
	 * We only accept hex here if the string contains a hex
	 * letter, is 8 chars long, or starts with 'c','e','8','4'
	 * which are the typical Windows NTSTATUS severity nibbles.
	 * Pure decimal-looking short strings should not be
	 * reinterpreted as hex. */
	if (is_all_hex(buf)) {
		int has_letter = 0;
		for (i = 0; i < n; i++) {
			unsigned char c = (unsigned char)buf[i];
			if ((c >= 'a' && c <= 'f') ||
			    (c >= 'A' && c <= 'F')) {
				has_letter = 1;
				break;
			}
		}
		if (has_letter || n == 8)
			return parse_hex32(buf, codep);
		/* otherwise fall through to decimal for short pure
		 * digit strings */
	}

	/* plain digits -> decimal */
	if (!has_alpha(buf) && buf[0] >= '0' && buf[0] <= '9')
		return parse_dec32(buf, codep);

	/* name lookup */
	for (i = 0; i < zexc_names_n; i++) {
		const struct zexc_ent *e = &zexc_names[i];
		if (ieq(buf, e->name) || ieq(buf, e->shortn)) {
			*codep = e->code;
			return 0;
		}
		if (e->alias != NULL && ieq(buf, e->alias)) {
			*codep = e->code;
			return 0;
		}
	}
	return -1;
}

/*
 * Defaults table: (code, stop, pass, print).  Entries not
 * listed fall through to the default "stop yes, pass yes, print
 * yes" policy, which matches the issue spec "all unknown
 * exceptions stop=yes pass=yes print=yes".
 */
struct zexc_default {
	uint32_t code;
	int stop;
	int pass;
	int print;
};

static const struct zexc_default zexc_defaults[] = {
	{ 0xc0000005, 1, 1, 1 },	/* access violation */
	{ 0xc000001d, 1, 1, 1 },	/* illegal instruction */
	{ 0xc0000094, 1, 1, 1 },	/* int divide by zero */
	{ 0xc000008e, 1, 1, 1 },	/* flt divide by zero */
	{ 0xc00000fd, 1, 1, 1 },	/* stack overflow */
	{ 0xc0000006, 1, 1, 1 },	/* in-page error */
	{ 0xc0000096, 1, 1, 1 },	/* priv instruction */
	/* debugger-internal normally */
	{ 0x80000003, 1, 0, 0 },	/* breakpoint */
	{ 0x80000004, 1, 0, 0 },	/* single step */
	/* noisy first-chance / informational */
	{ 0x80000001, 0, 1, 0 },	/* guard page */
	{ 0x40010006, 0, 1, 0 },	/* DbgPrintException */
	{ 0x4001000a, 0, 1, 0 },	/* DbgPrintException (wide) */
	{ 0xe06d7363, 0, 1, 0 }		/* MSVC C++ exception */
};

static const size_t zexc_defaults_n =
    sizeof(zexc_defaults) / sizeof(zexc_defaults[0]);

static struct zexc_policy *
zexc_find_mut(struct zexc_table *xt, uint32_t code)
{
	int i;
	if (xt == NULL)
		return NULL;
	for (i = 0; i < xt->count; i++) {
		if (xt->pol[i].code == code)
			return &xt->pol[i];
	}
	return NULL;
}

static struct zexc_policy *
zexc_add(struct zexc_table *xt, uint32_t code)
{
	struct zexc_policy *p;
	if (xt == NULL || xt->count >= ZDBG_MAX_EXCEPTIONS)
		return NULL;
	p = &xt->pol[xt->count++];
	p->code = code;
	p->stop = xt->defpol.stop;
	p->pass = xt->defpol.pass;
	p->print = xt->defpol.print;
	return p;
}

void
zexc_table_init(struct zexc_table *xt)
{
	size_t i;

	if (xt == NULL)
		return;
	memset(xt, 0, sizeof(*xt));
	xt->defpol.code = 0;
	xt->defpol.stop = 1;
	xt->defpol.pass = 1;
	xt->defpol.print = 1;

	/* Pre-populate entries for every named code so `handle`
	 * without arguments shows a useful table, then apply the
	 * explicit defaults above. */
	for (i = 0; i < zexc_names_n; i++) {
		struct zexc_policy *p;
		if (xt->count >= ZDBG_MAX_EXCEPTIONS)
			break;
		p = &xt->pol[xt->count++];
		p->code = zexc_names[i].code;
		p->stop = xt->defpol.stop;
		p->pass = xt->defpol.pass;
		p->print = xt->defpol.print;
	}
	for (i = 0; i < zexc_defaults_n; i++) {
		struct zexc_policy *p;
		p = zexc_find_mut(xt, zexc_defaults[i].code);
		if (p == NULL)
			p = zexc_add(xt, zexc_defaults[i].code);
		if (p == NULL)
			continue;
		p->stop = zexc_defaults[i].stop ? 1 : 0;
		p->pass = zexc_defaults[i].pass ? 1 : 0;
		p->print = zexc_defaults[i].print ? 1 : 0;
	}
}

const struct zexc_policy *
zexc_get_policy(const struct zexc_table *xt, uint32_t code)
{
	int i;
	if (xt == NULL)
		return NULL;
	for (i = 0; i < xt->count; i++) {
		if (xt->pol[i].code == code)
			return &xt->pol[i];
	}
	return &xt->defpol;
}

int
zexc_set_policy(struct zexc_table *xt, uint32_t code,
    int set_stop, int stop,
    int set_pass, int pass,
    int set_print, int print)
{
	struct zexc_policy *p;
	if (xt == NULL)
		return -1;
	p = zexc_find_mut(xt, code);
	if (p == NULL) {
		p = zexc_add(xt, code);
		if (p == NULL)
			return -1;
	}
	if (set_stop)
		p->stop = stop ? 1 : 0;
	if (set_pass)
		p->pass = pass ? 1 : 0;
	if (set_print)
		p->print = print ? 1 : 0;
	return 0;
}

void
zexc_print_one(uint32_t code, const struct zexc_policy *p)
{
	if (p == NULL)
		return;
	printf(" %-34s %-4s %-4s %-4s\n", zexc_name(code),
	    p->stop  ? "yes" : "no",
	    p->pass  ? "yes" : "no",
	    p->print ? "yes" : "no");
}

void
zexc_print_table(const struct zexc_table *xt)
{
	int i;

	if (xt == NULL)
		return;
	printf(" Exception                          Stop Pass Print\n");
	for (i = 0; i < xt->count; i++)
		zexc_print_one(xt->pol[i].code, &xt->pol[i]);
}

void
zexc_print_names(void)
{
	size_t i;
	for (i = 0; i < zexc_names_n; i++)
		printf(" 0x%08x %s\n",
		    (unsigned int)zexc_names[i].code, zexc_names[i].name);
}
