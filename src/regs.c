/*
 * regs.c - register snapshot helpers.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "zdbg_regs.h"

struct reg_entry {
	const char *name;
	size_t offset;
};

#define REG_OFF(field) ((size_t)&(((struct zregs *)0)->field))

static const struct reg_entry reg_table[] = {
	{ "rax",    REG_OFF(rax) },
	{ "rbx",    REG_OFF(rbx) },
	{ "rcx",    REG_OFF(rcx) },
	{ "rdx",    REG_OFF(rdx) },
	{ "rsi",    REG_OFF(rsi) },
	{ "rdi",    REG_OFF(rdi) },
	{ "rbp",    REG_OFF(rbp) },
	{ "rsp",    REG_OFF(rsp) },
	{ "r8",     REG_OFF(r8)  },
	{ "r9",     REG_OFF(r9)  },
	{ "r10",    REG_OFF(r10) },
	{ "r11",    REG_OFF(r11) },
	{ "r12",    REG_OFF(r12) },
	{ "r13",    REG_OFF(r13) },
	{ "r14",    REG_OFF(r14) },
	{ "r15",    REG_OFF(r15) },
	{ "rip",    REG_OFF(rip) },
	{ "rflags", REG_OFF(rflags) },
	/* aliases */
	{ "pc",     REG_OFF(rip) },
	{ "ip",     REG_OFF(rip) },
	{ "sp",     REG_OFF(rsp) },
	{ "flags",  REG_OFF(rflags) }
};

static const size_t reg_table_len = sizeof(reg_table) / sizeof(reg_table[0]);

static int
streq_ci(const char *a, const char *b)
{
	while (*a && *b) {
		unsigned char ca = (unsigned char)*a;
		unsigned char cb = (unsigned char)*b;
		if (tolower(ca) != tolower(cb))
			return 0;
		a++;
		b++;
	}
	return *a == 0 && *b == 0;
}

static const struct reg_entry *
reg_lookup(const char *name)
{
	size_t i;

	if (name == NULL)
		return NULL;
	for (i = 0; i < reg_table_len; i++) {
		if (streq_ci(name, reg_table[i].name))
			return &reg_table[i];
	}
	return NULL;
}

void
zregs_clear(struct zregs *r)
{
	if (r == NULL)
		return;
	memset(r, 0, sizeof(*r));
}

int
zregs_get_by_name(const struct zregs *r, const char *name, uint64_t *vp)
{
	const struct reg_entry *e;

	if (r == NULL || name == NULL || vp == NULL)
		return -1;
	e = reg_lookup(name);
	if (e == NULL)
		return -1;
	*vp = *(const uint64_t *)((const char *)r + e->offset);
	return 0;
}

int
zregs_set_by_name(struct zregs *r, const char *name, uint64_t v)
{
	const struct reg_entry *e;

	if (r == NULL || name == NULL)
		return -1;
	e = reg_lookup(name);
	if (e == NULL)
		return -1;
	*(uint64_t *)((char *)r + e->offset) = v;
	return 0;
}

void
zregs_print(const struct zregs *r)
{
	if (r == NULL)
		return;
	printf("rax=%016llx  rbx=%016llx  rcx=%016llx  rdx=%016llx\n",
	    (unsigned long long)r->rax, (unsigned long long)r->rbx,
	    (unsigned long long)r->rcx, (unsigned long long)r->rdx);
	printf("rsi=%016llx  rdi=%016llx  rbp=%016llx  rsp=%016llx\n",
	    (unsigned long long)r->rsi, (unsigned long long)r->rdi,
	    (unsigned long long)r->rbp, (unsigned long long)r->rsp);
	printf("r8 =%016llx  r9 =%016llx  r10=%016llx  r11=%016llx\n",
	    (unsigned long long)r->r8,  (unsigned long long)r->r9,
	    (unsigned long long)r->r10, (unsigned long long)r->r11);
	printf("r12=%016llx  r13=%016llx  r14=%016llx  r15=%016llx\n",
	    (unsigned long long)r->r12, (unsigned long long)r->r13,
	    (unsigned long long)r->r14, (unsigned long long)r->r15);
	printf("rip=%016llx  rflags=%016llx\n",
	    (unsigned long long)r->rip, (unsigned long long)r->rflags);
}
