/*
 * symbols_elf.c - Linux ELF64 .symtab / .dynsym loader.
 *
 * Parses the mapped executable file(s) reported by
 * /proc/<pid>/maps and populates a fixed-size zsym_table.
 *
 * Scope is deliberately narrow:
 *   - ELF64 little-endian x86-64 only.
 *   - Reads .symtab + .strtab and/or .dynsym + .dynstr.
 *   - No DWARF, no relocation tables, no sections besides the
 *     symbol/string tables and the section header string table.
 *   - Runtime addresses are computed using the load bias
 *     derived from a chosen module mapping:
 *         load_bias    = map.start - map.offset
 *         runtime_addr = load_bias + st_value
 *     For ET_EXEC the formula is still applied; if the result
 *     is not inside any mapping we fall back to st_value.
 *
 * No external dependencies: we include <elf.h> for the ELF64
 * constants but isolate it here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <elf.h>

#include "zdbg_symbols.h"
#include "zdbg_maps.h"

/* Reasonable upper bounds to avoid pathological files. */
#define ZDBG_SYMBOL_MAX_TABLE_BYTES (16 * 1024 * 1024)
#define ZDBG_SYMBOL_MAX_STRTAB_BYTES (16 * 1024 * 1024)

static char
tolower_char(char c)
{
	if (c >= 'A' && c <= 'Z')
		return (char)(c - 'A' + 'a');
	return c;
}

static int
has_exec(const struct zmap *m)
{
	return strchr(m->perms, 'x') != NULL;
}

static int
is_file_backed(const struct zmap *m)
{
	if (m->name[0] == 0)
		return 0;
	if (m->name[0] == '[')
		return 0;
	return 1;
}

/*
 * Pick the mapping used for load-bias computation for a given
 * pathname.  Preference: first executable mapping for that
 * path, otherwise first mapping.
 */
static const struct zmap *
pick_module_map(const struct zmap_table *maps, const char *path)
{
	const struct zmap *first = NULL;
	const struct zmap *first_x = NULL;
	int i;

	for (i = 0; i < maps->count; i++) {
		const struct zmap *m = &maps->maps[i];
		if (strcmp(m->name, path) != 0)
			continue;
		if (first == NULL)
			first = m;
		if (has_exec(m) && first_x == NULL)
			first_x = m;
	}
	if (first_x)
		return first_x;
	return first;
}

static int
pathname_already_processed(char paths[][ZDBG_SYM_MODULE_MAX], int n,
    const char *path)
{
	int i;
	for (i = 0; i < n; i++) {
		if (strcmp(paths[i], path) == 0)
			return 1;
	}
	return 0;
}

/*
 * Check that row isn't already present (same module, name,
 * address).  Simple linear scan: fine for ZDBG_MAX_SYMBOLS.
 */
static int
already_have_sym(const struct zsym_table *st, const char *module,
    const char *name, zaddr_t addr)
{
	int i;
	for (i = 0; i < st->count; i++) {
		const struct zsym *s = &st->syms[i];
		if (s->addr == addr && strcmp(s->name, name) == 0 &&
		    strcmp(s->module, module) == 0)
			return 1;
	}
	return 0;
}

static int
read_all(FILE *fp, long off, void *buf, size_t len)
{
	if (fseek(fp, off, SEEK_SET) != 0)
		return -1;
	if (fread(buf, 1, len, fp) != len)
		return -1;
	return 0;
}

/*
 * Load symbols of section shdr[idx] (which must be SHT_SYMTAB
 * or SHT_DYNSYM) into st.  The file is already validated as
 * ELF64 LSB.
 */
static void
load_one_symtab(FILE *fp, const Elf64_Ehdr *eh, const Elf64_Shdr *shdrs,
    Elf64_Half idx, struct zsym_table *st, const char *modname,
    uint64_t load_bias, int is_exec)
{
	const Elf64_Shdr *sh = &shdrs[idx];
	const Elf64_Shdr *link;
	char *strtab;
	Elf64_Sym sym;
	uint64_t nsyms;
	uint64_t i;

	if (sh->sh_type != SHT_SYMTAB && sh->sh_type != SHT_DYNSYM)
		return;
	if (sh->sh_entsize == 0 || sh->sh_size == 0)
		return;
	if (sh->sh_entsize != sizeof(Elf64_Sym))
		return;
	if (sh->sh_size > ZDBG_SYMBOL_MAX_TABLE_BYTES)
		return;
	if (sh->sh_link >= eh->e_shnum)
		return;
	link = &shdrs[sh->sh_link];
	if (link->sh_type != SHT_STRTAB)
		return;
	if (link->sh_size == 0 || link->sh_size > ZDBG_SYMBOL_MAX_STRTAB_BYTES)
		return;

	strtab = (char *)malloc((size_t)link->sh_size);
	if (strtab == NULL)
		return;
	if (read_all(fp, (long)link->sh_offset, strtab,
	    (size_t)link->sh_size) != 0) {
		free(strtab);
		return;
	}
	/* Guarantee NUL termination at end for safety. */
	strtab[link->sh_size - 1] = 0;

	nsyms = sh->sh_size / sh->sh_entsize;
	for (i = 0; i < nsyms; i++) {
		unsigned char type;
		unsigned char bind;
		char row_type;
		char row_bind;
		zaddr_t addr;
		const char *name;
		size_t nlen;
		struct zsym *out;

		if (st->count >= ZDBG_MAX_SYMBOLS) {
			st->truncated = 1;
			break;
		}
		if (read_all(fp,
		    (long)(sh->sh_offset + i * sh->sh_entsize),
		    &sym, sizeof(sym)) != 0)
			break;

		if (sym.st_shndx == SHN_UNDEF)
			continue;
		if (sym.st_name == 0 || sym.st_name >= link->sh_size)
			continue;
		name = strtab + sym.st_name;
		if (name[0] == 0)
			continue;

		type = ELF64_ST_TYPE(sym.st_info);
		bind = ELF64_ST_BIND(sym.st_info);

		switch (type) {
		case STT_FUNC:
#ifdef STT_GNU_IFUNC
		case STT_GNU_IFUNC:
#endif
			row_type = 'T';
			break;
		case STT_OBJECT:
			row_type = 'D';
			break;
		case STT_NOTYPE:
			row_type = '?';
			break;
		default:
			continue;
		}
		switch (bind) {
		case STB_GLOBAL:
		case STB_WEAK:
			row_bind = 'G';
			break;
		case STB_LOCAL:
			row_bind = 'L';
			row_type = (char)tolower_char(row_type);
			break;
		default:
			continue;
		}

		if (sym.st_value == 0)
			continue;

		if (is_exec) {
			/* ET_EXEC: st_value is absolute. */
			(void)load_bias;
			addr = (zaddr_t)sym.st_value;
		} else {
			addr = (zaddr_t)(load_bias + sym.st_value);
		}

		if (already_have_sym(st, modname, name, addr))
			continue;

		out = &st->syms[st->count];
		out->addr = addr;
		out->size = sym.st_size;
		out->type = row_type;
		out->bind = row_bind;
		nlen = strlen(name);
		if (nlen >= ZDBG_SYM_NAME_MAX)
			nlen = ZDBG_SYM_NAME_MAX - 1;
		memcpy(out->name, name, nlen);
		out->name[nlen] = 0;
		strncpy(out->module, modname, ZDBG_SYM_MODULE_MAX - 1);
		out->module[ZDBG_SYM_MODULE_MAX - 1] = 0;
		st->count++;
	}
	free(strtab);
}

static void
load_elf_file(const char *path, const char *modname,
    uint64_t load_bias, struct zsym_table *st)
{
	FILE *fp;
	Elf64_Ehdr eh;
	Elf64_Shdr *shdrs = NULL;
	size_t shdr_bytes;
	int is_exec = 0;
	int i;

	fp = fopen(path, "rb");
	if (fp == NULL)
		return;
	if (fread(&eh, 1, sizeof(eh), fp) != sizeof(eh))
		goto done;
	if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0)
		goto done;
	if (eh.e_ident[EI_CLASS] != ELFCLASS64)
		goto done;
	if (eh.e_ident[EI_DATA] != ELFDATA2LSB)
		goto done;
	if (eh.e_machine != EM_X86_64)
		goto done;
	if (eh.e_shentsize != sizeof(Elf64_Shdr))
		goto done;
	if (eh.e_shnum == 0)
		goto done;
	if (eh.e_type == ET_EXEC)
		is_exec = 1;
	else if (eh.e_type != ET_DYN)
		goto done;

	shdr_bytes = (size_t)eh.e_shnum * sizeof(Elf64_Shdr);
	if (shdr_bytes > ZDBG_SYMBOL_MAX_TABLE_BYTES)
		goto done;
	shdrs = (Elf64_Shdr *)malloc(shdr_bytes);
	if (shdrs == NULL)
		goto done;
	if (read_all(fp, (long)eh.e_shoff, shdrs, shdr_bytes) != 0)
		goto done;

	for (i = 0; i < eh.e_shnum; i++) {
		if (st->count >= ZDBG_MAX_SYMBOLS) {
			st->truncated = 1;
			break;
		}
		if (shdrs[i].sh_type == SHT_SYMTAB ||
		    shdrs[i].sh_type == SHT_DYNSYM) {
			load_one_symtab(fp, &eh, shdrs, (Elf64_Half)i,
			    st, modname, load_bias, is_exec);
		}
	}

done:
	if (shdrs != NULL)
		free(shdrs);
	fclose(fp);
}

int
zsyms_refresh(struct ztarget *t, const struct zmap_table *maps,
    struct zsym_table *st)
{
	/* Track which pathnames we have already scanned. */
	char seen[ZDBG_MAX_MAPS][ZDBG_SYM_MODULE_MAX];
	int nseen = 0;
	int i;
	int scanned = 0;

	(void)t;
	if (st == NULL)
		return -1;
	zsyms_clear(st);
	if (maps == NULL)
		return 0;

	for (i = 0; i < maps->count; i++) {
		const struct zmap *m = &maps->maps[i];
		const struct zmap *sel;
		uint64_t bias;

		if (st->count >= ZDBG_MAX_SYMBOLS) {
			st->truncated = 1;
			break;
		}
		if (!is_file_backed(m))
			continue;
		if (pathname_already_processed(seen, nseen, m->name))
			continue;
		if (nseen < ZDBG_MAX_MAPS) {
			strncpy(seen[nseen], m->name,
			    ZDBG_SYM_MODULE_MAX - 1);
			seen[nseen][ZDBG_SYM_MODULE_MAX - 1] = 0;
			nseen++;
		}
		sel = pick_module_map(maps, m->name);
		if (sel == NULL)
			continue;
		bias = (uint64_t)(sel->start - sel->offset);
		load_elf_file(m->name, m->name, bias, st);
		scanned++;
	}
	return scanned;
}
