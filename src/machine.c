/*
 * machine.c - executable machine detection.
 *
 * Tiny on-disk parser for ELF64 and PE32+ headers, sufficient
 * to map a launch target file to an enum zarch identifier.  No
 * external libraries; all magic numbers and offsets are defined
 * locally so this builds the same on Linux and Windows hosts.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_machine.h"

/* --- helpers --------------------------------------------------- */

static void
set_err(char *err, size_t errcap, const char *msg)
{
	size_t n;

	if (err == NULL || errcap == 0)
		return;
	n = strlen(msg);
	if (n >= errcap)
		n = errcap - 1;
	memcpy(err, msg, n);
	err[n] = 0;
}

static int
read_at(FILE *fp, long off, void *buf, size_t len)
{
	if (fp == NULL || buf == NULL)
		return -1;
	if (fseek(fp, off, SEEK_SET) != 0)
		return -1;
	if (fread(buf, 1, len, fp) != len)
		return -1;
	return 0;
}

static uint16_t
rd_le16(const unsigned char *p)
{
	return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t
rd_le32(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	    ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* --- ELF parsing ----------------------------------------------- */

/*
 * Minimal ELF identification fields we care about.  Defined
 * locally so the module builds on Windows hosts without
 * <elf.h>.
 */
#define ZELF_EI_CLASS    4
#define ZELF_EI_DATA     5
#define ZELF_CLASS32     1
#define ZELF_CLASS64     2
#define ZELF_DATA2LSB    1
#define ZELF_DATA2MSB    2

/* Offset of e_machine in Elf64_Ehdr is 0x12 (after ident[16],
 * e_type[2]).  Little-endian ELF64 only is required for now. */
#define ZELF64_EMACHINE_OFF 0x12

#define ZEM_X86_64   62
#define ZEM_AARCH64  183

static int
detect_elf(FILE *fp, enum zarch *archp, char *err, size_t errcap)
{
	unsigned char ident[16];
	unsigned char emach[2];
	uint16_t machine;

	if (read_at(fp, 0, ident, sizeof(ident)) < 0) {
		set_err(err, errcap, "short read on ELF identification");
		return -1;
	}
	if (ident[0] != 0x7f || ident[1] != 'E' || ident[2] != 'L' ||
	    ident[3] != 'F') {
		set_err(err, errcap,
		    "could not detect target machine: not an ELF or PE "
		    "executable");
		return -1;
	}
	if (ident[ZELF_EI_CLASS] == ZELF_CLASS32) {
		set_err(err, errcap, "unsupported ELF class: 32-bit");
		return -2;
	}
	if (ident[ZELF_EI_CLASS] != ZELF_CLASS64) {
		set_err(err, errcap, "unsupported ELF class");
		return -2;
	}
	if (ident[ZELF_EI_DATA] != ZELF_DATA2LSB) {
		set_err(err, errcap, "unsupported ELF data encoding: "
		    "big-endian");
		return -2;
	}
	if (read_at(fp, ZELF64_EMACHINE_OFF, emach, sizeof(emach)) < 0) {
		set_err(err, errcap, "short read on ELF e_machine");
		return -1;
	}
	machine = rd_le16(emach);
	switch (machine) {
	case ZEM_X86_64:
		if (archp != NULL)
			*archp = ZARCH_X86_64;
		return 0;
	case ZEM_AARCH64:
		if (archp != NULL)
			*archp = ZARCH_AARCH64;
		return 0;
	default: {
		char buf[64];
		snprintf(buf, sizeof(buf),
		    "unsupported ELF e_machine: 0x%x", (unsigned)machine);
		set_err(err, errcap, buf);
		return -2;
	}
	}
}

/* --- PE parsing ------------------------------------------------ */

#define ZPE_E_LFANEW_OFF                0x3c
#define ZPE_FILEHEADER_MACHINE_OFF      4   /* after "PE\0\0" */
#define ZPE_FILEHEADER_SIZE_OF_OPT_OFF  20
#define ZPE_OPTHDR_OFF                  24  /* after "PE\0\0" */

/*
 * Conservative upper bound for PE e_lfanew.  Real PE images have
 * e_lfanew well under a few KB; treat anything multi-megabyte as
 * a corrupt or hostile header and refuse to chase it.
 */
#define ZPE_MAX_LFANEW                  0x10000000

#define ZIMAGE_FILE_MACHINE_AMD64        0x8664
#define ZIMAGE_FILE_MACHINE_ARM64        0xaa64
#define ZIMAGE_FILE_MACHINE_I386         0x014c
#define ZIMAGE_NT_OPTIONAL_HDR64_MAGIC   0x20b
#define ZIMAGE_NT_OPTIONAL_HDR32_MAGIC   0x10b

static int
detect_pe(FILE *fp, long pe_off, enum zarch *archp,
    char *err, size_t errcap)
{
	unsigned char sig[4];
	unsigned char fhdr[20]; /* IMAGE_FILE_HEADER */
	unsigned char optmag[2];
	uint16_t machine;
	uint16_t magic;
	uint16_t opt_size;

	if (read_at(fp, pe_off, sig, sizeof(sig)) < 0) {
		set_err(err, errcap, "short read on PE signature");
		return -1;
	}
	if (sig[0] != 'P' || sig[1] != 'E' || sig[2] != 0 ||
	    sig[3] != 0) {
		set_err(err, errcap,
		    "could not detect target machine: not an ELF or PE "
		    "executable");
		return -1;
	}
	if (read_at(fp, pe_off + 4, fhdr, sizeof(fhdr)) < 0) {
		set_err(err, errcap, "short read on PE file header");
		return -1;
	}
	machine = rd_le16(&fhdr[0]);
	opt_size = rd_le16(&fhdr[16]);
	if (opt_size >= 2) {
		if (read_at(fp, pe_off + ZPE_OPTHDR_OFF, optmag,
		    sizeof(optmag)) == 0) {
			magic = rd_le16(optmag);
			if (magic == ZIMAGE_NT_OPTIONAL_HDR32_MAGIC) {
				set_err(err, errcap,
				    "unsupported PE: 32-bit (PE32)");
				return -2;
			}
			if (magic != ZIMAGE_NT_OPTIONAL_HDR64_MAGIC &&
			    magic != 0) {
				char buf[64];
				snprintf(buf, sizeof(buf),
				    "unsupported PE optional header magic: "
				    "0x%x", (unsigned)magic);
				set_err(err, errcap, buf);
				return -2;
			}
		}
	}
	switch (machine) {
	case ZIMAGE_FILE_MACHINE_AMD64:
		if (archp != NULL)
			*archp = ZARCH_X86_64;
		return 0;
	case ZIMAGE_FILE_MACHINE_ARM64:
		if (archp != NULL)
			*archp = ZARCH_AARCH64;
		return 0;
	default: {
		char buf[64];
		snprintf(buf, sizeof(buf),
		    "unsupported PE machine: 0x%04x",
		    (unsigned)machine);
		set_err(err, errcap, buf);
		return -2;
	}
	}
}

static int
detect_mz(FILE *fp, enum zarch *archp, char *err, size_t errcap)
{
	unsigned char lfanew[4];
	uint32_t pe_off;
	long fsize;

	if (read_at(fp, ZPE_E_LFANEW_OFF, lfanew, sizeof(lfanew)) < 0) {
		set_err(err, errcap,
		    "could not detect target machine: not an ELF or PE "
		    "executable");
		return -1;
	}
	pe_off = rd_le32(lfanew);
	/*
	 * Sanity bound on e_lfanew: must point past the MZ header
	 * (>= 0x40) and lie within ZPE_MAX_LFANEW.
	 */
	if (pe_off < 0x40 || pe_off > ZPE_MAX_LFANEW) {
		set_err(err, errcap,
		    "could not detect target machine: not an ELF or PE "
		    "executable");
		return -1;
	}
	if (fseek(fp, 0, SEEK_END) != 0) {
		set_err(err, errcap, "could not stat target file");
		return -1;
	}
	fsize = ftell(fp);
	if (fsize < 0 || (long)pe_off + 24 > fsize) {
		set_err(err, errcap,
		    "could not detect target machine: not an ELF or PE "
		    "executable");
		return -1;
	}
	return detect_pe(fp, (long)pe_off, archp, err, errcap);
}

/* --- public API ------------------------------------------------ */

int
zmachine_detect_file(const char *path, enum zarch *archp,
    char *err, size_t errcap)
{
	FILE *fp;
	unsigned char head[4];
	int rc;

	if (err != NULL && errcap > 0)
		err[0] = 0;
	if (path == NULL || path[0] == 0) {
		set_err(err, errcap, "empty target path");
		return -1;
	}
	fp = fopen(path, "rb");
	if (fp == NULL) {
		set_err(err, errcap, "could not open target file");
		return -1;
	}
	if (read_at(fp, 0, head, sizeof(head)) < 0) {
		set_err(err, errcap,
		    "could not detect target machine: file too small");
		fclose(fp);
		return -1;
	}
	if (head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' &&
	    head[3] == 'F') {
		rc = detect_elf(fp, archp, err, errcap);
	} else if (head[0] == 'M' && head[1] == 'Z') {
		rc = detect_mz(fp, archp, err, errcap);
	} else {
		set_err(err, errcap,
		    "could not detect target machine: not an ELF or PE "
		    "executable");
		rc = -1;
	}
	fclose(fp);
	return rc;
}
