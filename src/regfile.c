/*
 * regfile.c - generic integer register-file view.
 *
 * Phase-1 adapter: the descriptor and alias tables for x86-64
 * mirror what `struct zregs` already exposes, and conversion
 * helpers shuttle values between the two.  The AArch64 stub
 * leaves the register file empty so every lookup fails cleanly
 * until a real backend is wired up.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "zdbg_regfile.h"
#include "zdbg_regs.h"

/* --- per-architecture descriptor / alias tables ---------------- */

static const struct zreg_desc x86_64_desc[] = {
	{ "rax",    64, ZREG_ROLE_NONE, 1 },
	{ "rbx",    64, ZREG_ROLE_NONE, 1 },
	{ "rcx",    64, ZREG_ROLE_NONE, 1 },
	{ "rdx",    64, ZREG_ROLE_NONE, 1 },
	{ "rsi",    64, ZREG_ROLE_NONE, 1 },
	{ "rdi",    64, ZREG_ROLE_NONE, 1 },
	{ "rbp",    64, ZREG_ROLE_FP,   1 },
	{ "rsp",    64, ZREG_ROLE_SP,   1 },
	{ "r8",     64, ZREG_ROLE_NONE, 1 },
	{ "r9",     64, ZREG_ROLE_NONE, 1 },
	{ "r10",    64, ZREG_ROLE_NONE, 1 },
	{ "r11",    64, ZREG_ROLE_NONE, 1 },
	{ "r12",    64, ZREG_ROLE_NONE, 1 },
	{ "r13",    64, ZREG_ROLE_NONE, 1 },
	{ "r14",    64, ZREG_ROLE_NONE, 1 },
	{ "r15",    64, ZREG_ROLE_NONE, 1 },
	{ "rip",    64, ZREG_ROLE_PC,   1 },
	{ "rflags", 64, ZREG_ROLE_NONE, 1 }
};

#define X86_64_DESC_COUNT \
	((int)(sizeof(x86_64_desc) / sizeof(x86_64_desc[0])))

static const struct zreg_alias x86_64_aliases[] = {
	{ "pc",    "rip" },
	{ "ip",    "rip" },
	{ "sp",    "rsp" },
	{ "fp",    "rbp" },
	{ "flags", "rflags" }
};

#define X86_64_ALIAS_COUNT \
	((int)(sizeof(x86_64_aliases) / sizeof(x86_64_aliases[0])))

/* --- helpers --------------------------------------------------- */

static int
streq_ci(const char *a, const char *b)
{
	if (a == NULL || b == NULL)
		return 0;
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

static int
find_desc_index(const struct zreg_file *rf, const char *name)
{
	int i;

	if (rf == NULL || rf->desc == NULL || name == NULL)
		return -1;
	for (i = 0; i < rf->desc_count; i++) {
		if (streq_ci(rf->desc[i].name, name))
			return i;
	}
	return -1;
}

/*
 * Resolve `name` (possibly an alias) to a canonical descriptor
 * index in `rf`.  Returns -1 if unknown.
 */
static int
resolve_index(const struct zreg_file *rf, const char *name)
{
	int idx;
	int i;

	idx = find_desc_index(rf, name);
	if (idx >= 0)
		return idx;
	if (rf == NULL || rf->aliases == NULL)
		return -1;
	for (i = 0; i < rf->alias_count; i++) {
		if (streq_ci(rf->aliases[i].name, name))
			return find_desc_index(rf, rf->aliases[i].canonical);
	}
	return -1;
}

static int
find_role_index(const struct zreg_file *rf, enum zreg_role role)
{
	int i;

	if (rf == NULL || rf->desc == NULL || role == ZREG_ROLE_NONE)
		return -1;
	for (i = 0; i < rf->desc_count; i++) {
		if ((enum zreg_role)rf->desc[i].role == role)
			return i;
	}
	return -1;
}

/* --- public API ------------------------------------------------ */

void
zregfile_init(struct zreg_file *rf, enum zarch arch)
{
	if (rf == NULL)
		return;
	memset(rf, 0, sizeof(*rf));
	rf->arch = arch;
	if (arch == ZARCH_X86_64) {
		rf->desc = x86_64_desc;
		rf->desc_count = X86_64_DESC_COUNT;
		rf->aliases = x86_64_aliases;
		rf->alias_count = X86_64_ALIAS_COUNT;
		rf->count = X86_64_DESC_COUNT;
	}
	/* Other architectures (ZARCH_NONE, ZARCH_AARCH64) get an
	 * empty register file: every lookup fails cleanly. */
}

/*
 * Map an x86-64 descriptor index to the matching offset in
 * `struct zregs`.  Keeps the descriptor table and the legacy
 * struct in lockstep without offsetof gymnastics in the table.
 */
static size_t
x86_64_zregs_offset(int idx)
{
	switch (idx) {
	case 0:  return (size_t)&((struct zregs *)0)->rax;
	case 1:  return (size_t)&((struct zregs *)0)->rbx;
	case 2:  return (size_t)&((struct zregs *)0)->rcx;
	case 3:  return (size_t)&((struct zregs *)0)->rdx;
	case 4:  return (size_t)&((struct zregs *)0)->rsi;
	case 5:  return (size_t)&((struct zregs *)0)->rdi;
	case 6:  return (size_t)&((struct zregs *)0)->rbp;
	case 7:  return (size_t)&((struct zregs *)0)->rsp;
	case 8:  return (size_t)&((struct zregs *)0)->r8;
	case 9:  return (size_t)&((struct zregs *)0)->r9;
	case 10: return (size_t)&((struct zregs *)0)->r10;
	case 11: return (size_t)&((struct zregs *)0)->r11;
	case 12: return (size_t)&((struct zregs *)0)->r12;
	case 13: return (size_t)&((struct zregs *)0)->r13;
	case 14: return (size_t)&((struct zregs *)0)->r14;
	case 15: return (size_t)&((struct zregs *)0)->r15;
	case 16: return (size_t)&((struct zregs *)0)->rip;
	case 17: return (size_t)&((struct zregs *)0)->rflags;
	default: return (size_t)-1;
	}
}

int
zregfile_from_zregs(struct zreg_file *rf, enum zarch arch,
    const struct zregs *zr)
{
	int i;

	if (rf == NULL || zr == NULL)
		return -1;
	zregfile_init(rf, arch);
	if (arch != ZARCH_X86_64)
		return -1;
	for (i = 0; i < rf->desc_count; i++) {
		size_t off = x86_64_zregs_offset(i);
		const uint64_t *p =
		    (const uint64_t *)((const char *)zr + off);
		rf->val[i].value = *p;
		rf->val[i].valid = 1;
	}
	return 0;
}

int
zregfile_to_zregs(const struct zreg_file *rf, struct zregs *zr)
{
	int i;

	if (rf == NULL || zr == NULL)
		return -1;
	if (rf->arch != ZARCH_X86_64)
		return -1;
	for (i = 0; i < rf->desc_count; i++) {
		size_t off = x86_64_zregs_offset(i);
		uint64_t *p = (uint64_t *)((char *)zr + off);
		*p = rf->val[i].value;
	}
	return 0;
}

int
zregfile_get(const struct zreg_file *rf, const char *name, uint64_t *vp)
{
	int idx;

	if (rf == NULL || name == NULL || vp == NULL)
		return -1;
	idx = resolve_index(rf, name);
	if (idx < 0)
		return -1;
	if (!rf->val[idx].valid)
		return -1;
	*vp = rf->val[idx].value;
	return 0;
}

int
zregfile_set(struct zreg_file *rf, const char *name, uint64_t v)
{
	int idx;

	if (rf == NULL || name == NULL)
		return -1;
	idx = resolve_index(rf, name);
	if (idx < 0)
		return -1;
	if (!rf->desc[idx].writable)
		return -1;
	rf->val[idx].value = v;
	rf->val[idx].valid = 1;
	return 0;
}

int
zregfile_get_role(const struct zreg_file *rf, enum zreg_role role,
    uint64_t *vp)
{
	int idx;

	if (rf == NULL || vp == NULL)
		return -1;
	idx = find_role_index(rf, role);
	if (idx < 0)
		return -1;
	if (!rf->val[idx].valid)
		return -1;
	*vp = rf->val[idx].value;
	return 0;
}

int
zregfile_set_role(struct zreg_file *rf, enum zreg_role role, uint64_t v)
{
	int idx;

	if (rf == NULL)
		return -1;
	idx = find_role_index(rf, role);
	if (idx < 0)
		return -1;
	if (!rf->desc[idx].writable)
		return -1;
	rf->val[idx].value = v;
	rf->val[idx].valid = 1;
	return 0;
}

const char *
zregfile_role_name(const struct zreg_file *rf, enum zreg_role role)
{
	int idx;

	idx = find_role_index(rf, role);
	if (idx < 0)
		return NULL;
	return rf->desc[idx].name;
}

static void
print_x86_64(const struct zreg_file *rf)
{
	uint64_t v[18];
	int i;

	for (i = 0; i < 18; i++)
		v[i] = rf->val[i].valid ? rf->val[i].value : 0;
	printf("rax=%016llx  rbx=%016llx  rcx=%016llx  rdx=%016llx\n",
	    (unsigned long long)v[0], (unsigned long long)v[1],
	    (unsigned long long)v[2], (unsigned long long)v[3]);
	printf("rsi=%016llx  rdi=%016llx  rbp=%016llx  rsp=%016llx\n",
	    (unsigned long long)v[4], (unsigned long long)v[5],
	    (unsigned long long)v[6], (unsigned long long)v[7]);
	printf("r8 =%016llx  r9 =%016llx  r10=%016llx  r11=%016llx\n",
	    (unsigned long long)v[8],  (unsigned long long)v[9],
	    (unsigned long long)v[10], (unsigned long long)v[11]);
	printf("r12=%016llx  r13=%016llx  r14=%016llx  r15=%016llx\n",
	    (unsigned long long)v[12], (unsigned long long)v[13],
	    (unsigned long long)v[14], (unsigned long long)v[15]);
	printf("rip=%016llx  rflags=%016llx\n",
	    (unsigned long long)v[16], (unsigned long long)v[17]);
}

void
zregfile_print(const struct zreg_file *rf)
{
	int i;

	if (rf == NULL || rf->desc_count == 0) {
		printf("registers unsupported for this architecture\n");
		return;
	}
	if (rf->arch == ZARCH_X86_64) {
		print_x86_64(rf);
		return;
	}
	/* Generic fallback: one register per line. */
	for (i = 0; i < rf->desc_count; i++) {
		printf("%-7s = %016llx%s\n",
		    rf->desc[i].name,
		    (unsigned long long)rf->val[i].value,
		    rf->val[i].valid ? "" : " (invalid)");
	}
}
