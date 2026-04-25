/*
 * arch_aarch64_dis.c - AArch64 phase-1 disassembler/decoder.
 *
 * The goal of this module is narrow: make AArch64 instruction
 * streams readable enough for `u`, branch-target awareness, and
 * step-over of `bl`/`blr`.  It is not a full disassembler.
 *
 * Coverage:
 *   - NOP / HINT / BRK #imm / SVC #imm
 *   - Unconditional branch immediate (B / BL)
 *   - Compare-and-branch (CBZ / CBNZ)
 *   - Test-and-branch (TBZ / TBNZ)
 *   - Conditional branch immediate (B.cond)
 *   - Unconditional branch register (BR / BLR / RET)
 *   - PC-relative address formation (ADR / ADRP)
 *   - ADD/SUB immediate (with CMP/CMN/MOV-from-SP aliases)
 *   - STP/LDP signed-offset, pre-index and post-index forms
 *
 * Anything else is rendered as `.word 0xNNNNNNNN` with kind
 * ZINSN_OTHER and len 4.  Decoders that successfully recognize
 * an instruction set the appropriate metadata fields (kind,
 * has_target/target, is_call/is_branch/is_cond) used by `u`,
 * `p`, and symbol annotation.
 *
 * Style: small functions, explicit error paths, no VLAs, no
 * external dependencies.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "zdbg_arch.h"
#include "zdbg_arch_aarch64.h"

/* --- helpers -------------------------------------------------- */

/* Sign-extend the low `bits` of `v` to a 64-bit signed value,
 * returned as int64_t.  `bits` must be in 1..64. */
static int64_t
sx(uint64_t v, unsigned bits)
{
	uint64_t m;
	uint64_t s;

	if (bits >= 64)
		return (int64_t)v;
	m = ((uint64_t)1 << bits) - 1;
	v &= m;
	s = (uint64_t)1 << (bits - 1);
	if (v & s)
		v |= ~m;
	return (int64_t)v;
}

/*
 * Return canonical 64-bit register name for register number `r`.
 * `r` in 0..31; 31 is "sp" when the encoding context names SP and
 * "xzr" when it names the zero register.  Caller picks via `sp`.
 */
static const char *
xreg(unsigned r, int sp)
{
	static const char *const names[32] = {
		"x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
		"x8",  "x9",  "x10", "x11", "x12", "x13", "x14", "x15",
		"x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
		"x24", "x25", "x26", "x27", "x28", "x29", "x30", "xzr"
	};
	if (r > 31)
		return "x?";
	if (r == 31)
		return sp ? "sp" : "xzr";
	return names[r];
}

/* 32-bit register names. */
static const char *
wreg(unsigned r, int sp)
{
	static const char *const names[32] = {
		"w0",  "w1",  "w2",  "w3",  "w4",  "w5",  "w6",  "w7",
		"w8",  "w9",  "w10", "w11", "w12", "w13", "w14", "w15",
		"w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
		"w24", "w25", "w26", "w27", "w28", "w29", "w30", "wzr"
	};
	if (r > 31)
		return "w?";
	if (r == 31)
		return sp ? "wsp" : "wzr";
	return names[r];
}

/* Canonical condition-code suffixes for B.cond.  Index 0..15. */
static const char *
cond_name(unsigned c)
{
	static const char *const names[16] = {
		"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
		"hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
	};
	if (c > 15)
		return "??";
	return names[c];
}

static void
fill_word(struct zdecode *out, uint32_t insn)
{
	snprintf(out->text, sizeof(out->text), ".word 0x%08x",
	    (unsigned)insn);
	out->kind = ZINSN_OTHER;
}

/* --- decoders for each instruction class ---------------------- */

/*
 * BRK / HINT (NOP) / SVC / RET / BR / BLR: the system/branch-reg
 * group at top-level.  Returns 1 if handled, 0 otherwise.
 */
static int
decode_brsys(uint32_t insn, struct zdecode *out)
{
	/* nop = D503 201F.  HINT family covers the encoding space
	 * D503 20xx; the only mnemonic we print is plain `nop`,
	 * everything else falls through to the catch-all hint. */
	if (insn == 0xd503201fu) {
		snprintf(out->text, sizeof(out->text), "nop");
		out->kind = ZINSN_NOP;
		return 1;
	}
	if ((insn & 0xfffff01fu) == 0xd503201fu) {
		unsigned crm = (insn >> 8) & 0xf;
		unsigned op2 = (insn >> 5) & 0x7;
		unsigned imm = (crm << 3) | op2;
		snprintf(out->text, sizeof(out->text), "hint #%u", imm);
		out->kind = ZINSN_OTHER;
		return 1;
	}
	/* BRK #imm16: D420 0000 | imm16 << 5. */
	if ((insn & 0xffe0001fu) == 0xd4200000u) {
		unsigned imm = (insn >> 5) & 0xffff;
		snprintf(out->text, sizeof(out->text), "brk #%u", imm);
		out->kind = ZINSN_BREAKPOINT;
		return 1;
	}
	/* SVC #imm16: D400 0001 | imm16 << 5. */
	if ((insn & 0xffe0001fu) == 0xd4000001u) {
		unsigned imm = (insn >> 5) & 0xffff;
		snprintf(out->text, sizeof(out->text), "svc #%u", imm);
		out->kind = ZINSN_OTHER;
		return 1;
	}
	/* RET xN: D65F 0000 | rn << 5.  Default xN is x30. */
	if ((insn & 0xfffffc1fu) == 0xd65f0000u) {
		unsigned rn = (insn >> 5) & 0x1f;
		if (rn == 30)
			snprintf(out->text, sizeof(out->text), "ret");
		else
			snprintf(out->text, sizeof(out->text), "ret %s",
			    xreg(rn, 0));
		out->kind = ZINSN_RET;
		out->is_branch = 1;
		return 1;
	}
	/* BR xN: D61F 0000 | rn << 5. */
	if ((insn & 0xfffffc1fu) == 0xd61f0000u) {
		unsigned rn = (insn >> 5) & 0x1f;
		snprintf(out->text, sizeof(out->text), "br %s",
		    xreg(rn, 0));
		out->kind = ZINSN_JMP;
		out->is_branch = 1;
		return 1;
	}
	/* BLR xN: D63F 0000 | rn << 5. */
	if ((insn & 0xfffffc1fu) == 0xd63f0000u) {
		unsigned rn = (insn >> 5) & 0x1f;
		snprintf(out->text, sizeof(out->text), "blr %s",
		    xreg(rn, 0));
		out->kind = ZINSN_CALL;
		out->is_branch = 1;
		out->is_call = 1;
		return 1;
	}
	return 0;
}

/*
 * B / BL: unconditional branch immediate.  imm26 is signed,
 * scaled by 4, target = pc + sx(imm26<<2, 28).
 */
static int
decode_b_bl(zaddr_t addr, uint32_t insn, struct zdecode *out)
{
	uint32_t op = insn >> 26;
	int is_bl;
	int64_t off;
	zaddr_t target;
	uint32_t imm26;

	if (op == 0x05u)        /* 000101 */
		is_bl = 0;
	else if (op == 0x25u)   /* 100101 */
		is_bl = 1;
	else
		return 0;
	imm26 = insn & 0x03ffffffu;
	off = sx((uint64_t)imm26 << 2, 28);
	target = (zaddr_t)((int64_t)addr + off);
	snprintf(out->text, sizeof(out->text), "%s 0x%llx",
	    is_bl ? "bl" : "b",
	    (unsigned long long)target);
	out->is_branch = 1;
	out->has_target = 1;
	out->target = target;
	if (is_bl) {
		out->kind = ZINSN_CALL;
		out->is_call = 1;
	} else {
		out->kind = ZINSN_JMP;
	}
	return 1;
}

/*
 * Conditional branch immediate B.cond: bits 31-24 = 0x54, bit 4 = 0.
 * imm19 in bits 23-5 is signed and scaled by 4.
 */
static int
decode_bcond(zaddr_t addr, uint32_t insn, struct zdecode *out)
{
	uint32_t imm19;
	unsigned cond;
	int64_t off;
	zaddr_t target;

	if ((insn & 0xff000010u) != 0x54000000u)
		return 0;
	imm19 = (insn >> 5) & 0x7ffffu;
	cond = insn & 0xfu;
	off = sx((uint64_t)imm19 << 2, 21);
	target = (zaddr_t)((int64_t)addr + off);
	snprintf(out->text, sizeof(out->text), "b.%s 0x%llx",
	    cond_name(cond), (unsigned long long)target);
	out->kind = ZINSN_JCC;
	out->is_branch = 1;
	out->is_cond = 1;
	out->has_target = 1;
	out->target = target;
	return 1;
}

/*
 * CBZ / CBNZ: bits 30-24 = 0110100 (CBZ) or 0110101 (CBNZ).
 * sf in bit 31 selects 64-bit (1) or 32-bit (0) register.
 * imm19 in bits 23-5 is signed and scaled by 4.
 */
static int
decode_cb(zaddr_t addr, uint32_t insn, struct zdecode *out)
{
	uint32_t op = (insn >> 24) & 0x7fu;
	int is_nz;
	int sf;
	unsigned rt;
	uint32_t imm19;
	int64_t off;
	zaddr_t target;

	if (op == 0x34u)
		is_nz = 0;
	else if (op == 0x35u)
		is_nz = 1;
	else
		return 0;
	sf = (insn >> 31) & 1;
	rt = insn & 0x1fu;
	imm19 = (insn >> 5) & 0x7ffffu;
	off = sx((uint64_t)imm19 << 2, 21);
	target = (zaddr_t)((int64_t)addr + off);
	snprintf(out->text, sizeof(out->text), "%s %s, 0x%llx",
	    is_nz ? "cbnz" : "cbz",
	    sf ? xreg(rt, 0) : wreg(rt, 0),
	    (unsigned long long)target);
	out->kind = ZINSN_JCC;
	out->is_branch = 1;
	out->is_cond = 1;
	out->has_target = 1;
	out->target = target;
	return 1;
}

/*
 * TBZ / TBNZ: bits 30-24 = 0110110 (TBZ) or 0110111 (TBNZ).
 * Bit-position is { b5(=bit 31), b40(=bits 23-19) } (6 bits).
 * imm14 is in bits 18-5, signed, scaled by 4.
 */
static int
decode_tb(zaddr_t addr, uint32_t insn, struct zdecode *out)
{
	uint32_t op = (insn >> 24) & 0x7fu;
	int is_nz;
	unsigned b5;
	unsigned b40;
	unsigned bit;
	unsigned rt;
	uint32_t imm14;
	int64_t off;
	zaddr_t target;
	const char *rname;

	if (op == 0x36u)
		is_nz = 0;
	else if (op == 0x37u)
		is_nz = 1;
	else
		return 0;
	b5 = (insn >> 31) & 1u;
	b40 = (insn >> 19) & 0x1fu;
	bit = (b5 << 5) | b40;
	rt = insn & 0x1fu;
	imm14 = (insn >> 5) & 0x3fffu;
	off = sx((uint64_t)imm14 << 2, 16);
	target = (zaddr_t)((int64_t)addr + off);
	/* The architecture names the register as Xt regardless of
	 * bit position, but b5==0 implies the bit is in the low 32
	 * bits.  Print Wt when b5==0 to match canonical disassembly
	 * of common compilers; otherwise Xt. */
	rname = b5 ? xreg(rt, 0) : wreg(rt, 0);
	snprintf(out->text, sizeof(out->text), "%s %s, #%u, 0x%llx",
	    is_nz ? "tbnz" : "tbz", rname, bit,
	    (unsigned long long)target);
	out->kind = ZINSN_JCC;
	out->is_branch = 1;
	out->is_cond = 1;
	out->has_target = 1;
	out->target = target;
	return 1;
}

/*
 * ADR / ADRP: PC-relative address formation.
 *   ADR  : op = 0, target = pc + sx(imm21, 21)
 *   ADRP : op = 1, target = (pc & ~0xfff) + sx(imm21<<12, 33)
 * Encoding: op(1) | immlo(2) | 10000 | immhi(19) | Rd(5).
 */
static int
decode_adr(zaddr_t addr, uint32_t insn, struct zdecode *out)
{
	unsigned op;
	unsigned rd;
	uint32_t immlo;
	uint32_t immhi;
	uint32_t imm21;
	int64_t off;
	zaddr_t target;

	if ((insn & 0x1f000000u) != 0x10000000u)
		return 0;
	op = (insn >> 31) & 1u;
	rd = insn & 0x1fu;
	immlo = (insn >> 29) & 0x3u;
	immhi = (insn >> 5) & 0x7ffffu;
	imm21 = (immhi << 2) | immlo;
	if (op == 0) {
		off = sx(imm21, 21);
		target = (zaddr_t)((int64_t)addr + off);
		snprintf(out->text, sizeof(out->text),
		    "adr %s, 0x%llx", xreg(rd, 0),
		    (unsigned long long)target);
	} else {
		off = sx((uint64_t)imm21 << 12, 33);
		target = (zaddr_t)(((int64_t)(addr & ~(zaddr_t)0xfff))
		    + off);
		snprintf(out->text, sizeof(out->text),
		    "adrp %s, 0x%llx", xreg(rd, 0),
		    (unsigned long long)target);
	}
	out->kind = ZINSN_LEA;
	out->has_target = 1;
	out->target = target;
	return 1;
}

/*
 * ADD/SUB (immediate).  Encoding (data-processing immediate
 * subclass 100):
 *   sf op S 100010 sh imm12 Rn Rd
 *   op=0 ADD/ADDS, op=1 SUB/SUBS, S=1 sets flags.
 *   sh selects shift of imm12: 0 -> #0, 1 -> #12.
 *
 * Aliases handled here:
 *   - SUBS Rd=ZR     -> CMP
 *   - ADDS Rd=ZR     -> CMN
 *   - ADD imm=0,sh=0 with Rd or Rn == SP -> MOV (to/from SP)
 */
static int
decode_addsub_imm(uint32_t insn, struct zdecode *out)
{
	int sf;
	int op;
	int S;
	unsigned sh;
	unsigned imm12;
	unsigned rn;
	unsigned rd;
	const char *(*r)(unsigned, int);
	const char *mnem;
	uint32_t imm;
	int rd_is_sp_or_zr;
	int rn_is_sp_or_zr;

	if ((insn & 0x1f000000u) != 0x11000000u)
		return 0;

	sf = (insn >> 31) & 1;
	op = (insn >> 30) & 1;
	S = (insn >> 29) & 1;
	sh = (insn >> 22) & 0x3u;
	if (sh > 1)
		return 0;       /* reserved */
	imm12 = (insn >> 10) & 0xfffu;
	rn = (insn >> 5) & 0x1fu;
	rd = insn & 0x1fu;
	r = sf ? xreg : wreg;
	imm = (uint32_t)imm12 << (sh ? 12 : 0);

	rd_is_sp_or_zr = (rd == 31);
	rn_is_sp_or_zr = (rn == 31);

	/* MOV (to/from SP) alias: ADD (immediate), S=0, op=0,
	 * imm=0, sh=0, with Rd==SP or Rn==SP. */
	if (op == 0 && S == 0 && imm12 == 0 && sh == 0 &&
	    (rd_is_sp_or_zr || rn_is_sp_or_zr)) {
		snprintf(out->text, sizeof(out->text),
		    "mov %s, %s",
		    r(rd, 1), r(rn, 1));
		out->kind = ZINSN_MOV;
		return 1;
	}

	/* CMP / CMN aliases: SUBS/ADDS with Rd == ZR. */
	if (S == 1 && rd == 31) {
		mnem = op ? "cmp" : "cmn";
		snprintf(out->text, sizeof(out->text),
		    "%s %s, #%u", mnem, r(rn, 1), imm);
		out->kind = ZINSN_CMP;
		return 1;
	}

	mnem = op ? (S ? "subs" : "sub") : (S ? "adds" : "add");
	/* Rd uses SP form when not setting flags (S=0); Rn always
	 * uses SP form (per architecture). */
	snprintf(out->text, sizeof(out->text),
	    "%s %s, %s, #%u", mnem,
	    S ? r(rd, 0) : r(rd, 1), r(rn, 1), imm);
	out->kind = op ? ZINSN_SUB : ZINSN_ADD;
	return 1;
}

/*
 * STP / LDP: load/store pair, signed-offset, pre-index, post-index.
 * Encoding (V==0 integer forms):
 *   opc(2) 101 0 V(1) idx(2) L(1) imm7(7) Rt2(5) Rn(5) Rt(5)
 *   opc=00 32-bit  (imm7 scaled by 4)
 *   opc=10 64-bit  (imm7 scaled by 8)
 *   idx=01 post-indexed: [Xn], #imm
 *   idx=10 signed offset: [Xn, #imm]
 *   idx=11 pre-indexed: [Xn, #imm]!
 *   idx=00 STNP/LDNP (non-temporal) - skipped
 */
static int
decode_ldstp(uint32_t insn, struct zdecode *out)
{
	unsigned opc;
	unsigned V;
	unsigned idx;
	unsigned L;
	int imm7_signed;
	int scale;
	int imm;
	unsigned rt;
	unsigned rt2;
	unsigned rn;
	const char *mnem;
	const char *(*r)(unsigned, int);

	if ((insn & 0x3a000000u) != 0x28000000u)
		return 0;       /* not LDP/STP integer */
	opc = (insn >> 30) & 0x3u;
	V = (insn >> 26) & 1u;
	if (V != 0)
		return 0;       /* skip SIMD/FP */
	idx = (insn >> 23) & 0x3u;
	L = (insn >> 22) & 1u;
	rt = insn & 0x1fu;
	rt2 = (insn >> 10) & 0x1fu;
	rn = (insn >> 5) & 0x1fu;
	imm7_signed = (int)sx((insn >> 15) & 0x7fu, 7);

	if (opc == 0) {
		scale = 4;
		r = wreg;
	} else if (opc == 2) {
		scale = 8;
		r = xreg;
	} else {
		return 0;       /* opc=01 reserved or 11 SIMD-only */
	}
	imm = imm7_signed * scale;
	mnem = L ? "ldp" : "stp";

	switch (idx) {
	case 1:
		/* post-indexed: [Xn], #imm */
		snprintf(out->text, sizeof(out->text),
		    "%s %s, %s, [%s], #%d", mnem,
		    r(rt, 0), r(rt2, 0), xreg(rn, 1), imm);
		break;
	case 3:
		/* pre-indexed: [Xn, #imm]! */
		snprintf(out->text, sizeof(out->text),
		    "%s %s, %s, [%s, #%d]!", mnem,
		    r(rt, 0), r(rt2, 0), xreg(rn, 1), imm);
		break;
	case 2:
		/* signed offset: [Xn, #imm] (omit ", #0" for clarity) */
		if (imm == 0)
			snprintf(out->text, sizeof(out->text),
			    "%s %s, %s, [%s]", mnem,
			    r(rt, 0), r(rt2, 0), xreg(rn, 1));
		else
			snprintf(out->text, sizeof(out->text),
			    "%s %s, %s, [%s, #%d]", mnem,
			    r(rt, 0), r(rt2, 0), xreg(rn, 1), imm);
		break;
	default:
		return 0;       /* idx=00 STNP/LDNP */
	}
	out->kind = L ? ZINSN_OTHER : ZINSN_OTHER;
	return 1;
}

/* --- public entry points -------------------------------------- */

int
zaarch64_decode_one(zaddr_t addr, const uint8_t *buf, size_t buflen,
    struct zdecode *out)
{
	uint32_t insn;

	if (out == NULL)
		return -1;
	memset(out, 0, sizeof(*out));
	if (buf == NULL || buflen < 4)
		return -1;

	insn = (uint32_t)buf[0]
	    | ((uint32_t)buf[1] << 8)
	    | ((uint32_t)buf[2] << 16)
	    | ((uint32_t)buf[3] << 24);

	out->addr = addr;
	out->len = 4;
	memcpy(out->bytes, buf, 4);

	if (decode_brsys(insn, out))
		return 0;
	if (decode_b_bl(addr, insn, out))
		return 0;
	if (decode_bcond(addr, insn, out))
		return 0;
	if (decode_cb(addr, insn, out))
		return 0;
	if (decode_tb(addr, insn, out))
		return 0;
	if (decode_adr(addr, insn, out))
		return 0;
	if (decode_addsub_imm(insn, out))
		return 0;
	if (decode_ldstp(insn, out))
		return 0;

	/* Unknown encoding: fall back to `.word 0x...`. */
	fill_word(out, insn);
	return 0;
}

zaddr_t
zaarch64_fallthrough(const struct zdecode *d)
{
	if (d == NULL || d->len == 0)
		return 0;
	return d->addr + 4;
}
