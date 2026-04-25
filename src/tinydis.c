/*
 * tinydis.c - small x86-64 disassembler subset.
 *
 * Strictly narrow: only the encodings we can format with
 * confidence are decoded.  Everything else falls back to
 * "db 0xNN" one byte at a time.  This keeps output honest for
 * an unassembler aimed at DEBUG.COM-style use, without pulling
 * in a full x86 decoder.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_tinydis.h"

static const char *reg64[16] = {
	"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
	"r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"
};

static const char *reg32[16] = {
	"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
	"r8d", "r9d", "r10d","r11d","r12d","r13d","r14d","r15d"
};

static void
copy_bytes(struct ztinydis *out, const uint8_t *buf, size_t n)
{
	size_t i;
	if (n > sizeof(out->bytes))
		n = sizeof(out->bytes);
	for (i = 0; i < n; i++)
		out->bytes[i] = buf[i];
	out->len = n;
}

static int32_t
read_rel32(const uint8_t *p)
{
	uint32_t v;
	v  = (uint32_t)p[0];
	v |= (uint32_t)p[1] << 8;
	v |= (uint32_t)p[2] << 16;
	v |= (uint32_t)p[3] << 24;
	return (int32_t)v;
}

static uint64_t
read_imm64(const uint8_t *p)
{
	uint64_t v = 0;
	int i;
	for (i = 0; i < 8; i++)
		v |= (uint64_t)p[i] << (i * 8);
	return v;
}

static void
emit_db(zaddr_t addr, const uint8_t *buf, struct ztinydis *out)
{
	memset(out, 0, sizeof(*out));
	out->addr = addr;
	copy_bytes(out, buf, 1);
	snprintf(out->text, sizeof(out->text), "db 0x%02x", buf[0]);
	out->kind = ZINSN_OTHER;
}

/*
 * Decode a ModRM memory operand (mod != 3) into text.  Returns
 * number of bytes consumed after the ModRM byte (SIB + displacement
 * bytes), or -1 if the addressing form is unsupported or the
 * buffer is too short.  Sets rip_rel/rip_disp when the operand is
 * RIP-relative [rip+disp32] so the caller can substitute an
 * absolute target.
 */
static int
decode_modrm_mem(uint8_t modrm, const uint8_t *after, size_t navail,
    int rex_b, int rex_x, char *buf, size_t buflen,
    int *rip_rel, int32_t *rip_disp)
{
	int mod = (modrm >> 6) & 3;
	int rm = modrm & 7;
	int base, index;

	if (rip_rel != NULL)
		*rip_rel = 0;
	if (mod == 3)
		return -1;

	if (rm == 4) {
		uint8_t sib;
		if (navail < 1)
			return -1;
		sib = after[0];
		index = ((sib >> 3) & 7) | (rex_x ? 8 : 0);
		base = (sib & 7) | (rex_b ? 8 : 0);
		/* Only support no-index SIB forms; real index means we
		 * would need a scaled-index printer we do not have. */
		if (index != 4)
			return -1;

		if (mod == 0 && (sib & 7) == 5) {
			int32_t d;
			if (navail < 5)
				return -1;
			d = read_rel32(after + 1);
			snprintf(buf, buflen, "[0x%lx]",
			    (unsigned long)(uint32_t)d);
			return 5;
		}
		if (mod == 0) {
			snprintf(buf, buflen, "[%s]", reg64[base]);
			return 1;
		}
		if (mod == 1) {
			int8_t d;
			if (navail < 2)
				return -1;
			d = (int8_t)after[1];
			if (d < 0)
				snprintf(buf, buflen, "[%s-0x%x]",
				    reg64[base], (unsigned)(-d));
			else
				snprintf(buf, buflen, "[%s+0x%x]",
				    reg64[base], (unsigned)d);
			return 2;
		}
		/* mod == 2 */
		{
			int32_t d;
			if (navail < 5)
				return -1;
			d = read_rel32(after + 1);
			if (d < 0)
				snprintf(buf, buflen, "[%s-0x%lx]",
				    reg64[base], (unsigned long)(-(long)d));
			else
				snprintf(buf, buflen, "[%s+0x%lx]",
				    reg64[base], (unsigned long)d);
			return 5;
		}
	}

	if (mod == 0 && rm == 5) {
		int32_t d;
		if (navail < 4)
			return -1;
		d = read_rel32(after);
		if (rip_rel != NULL)
			*rip_rel = 1;
		if (rip_disp != NULL)
			*rip_disp = d;
		/* Caller typically replaces with absolute [0xTARGET]. */
		snprintf(buf, buflen, "[rip+0x%lx]", (unsigned long)d);
		return 4;
	}

	{
		int reg = rm | (rex_b ? 8 : 0);
		if (mod == 0) {
			snprintf(buf, buflen, "[%s]", reg64[reg]);
			return 0;
		}
		if (mod == 1) {
			int8_t d;
			if (navail < 1)
				return -1;
			d = (int8_t)after[0];
			if (d < 0)
				snprintf(buf, buflen, "[%s-0x%x]",
				    reg64[reg], (unsigned)(-d));
			else
				snprintf(buf, buflen, "[%s+0x%x]",
				    reg64[reg], (unsigned)d);
			return 1;
		}
		/* mod == 2 */
		{
			int32_t d;
			if (navail < 4)
				return -1;
			d = read_rel32(after);
			if (d < 0)
				snprintf(buf, buflen, "[%s-0x%lx]",
				    reg64[reg], (unsigned long)(-(long)d));
			else
				snprintf(buf, buflen, "[%s+0x%lx]",
				    reg64[reg], (unsigned long)d);
			return 4;
		}
	}
}

/*
 * Map short Jcc low nibble to mnemonic.
 */
static const char *
jcc_name(uint8_t low)
{
	switch (low & 0xf) {
	case 0x0: return "jo";
	case 0x1: return "jno";
	case 0x2: return "jb";
	case 0x3: return "jae";
	case 0x4: return "jz";
	case 0x5: return "jnz";
	case 0x6: return "jbe";
	case 0x7: return "ja";
	case 0x8: return "js";
	case 0x9: return "jns";
	case 0xa: return "jp";
	case 0xb: return "jnp";
	case 0xc: return "jl";
	case 0xd: return "jge";
	case 0xe: return "jle";
	case 0xf: return "jg";
	}
	return "jcc";
}

int
ztinydis_one(zaddr_t addr, const uint8_t *buf, size_t buflen,
    struct ztinydis *out)
{
	size_t pos = 0;
	int rex_w = 0, rex_r = 0, rex_x = 0, rex_b = 0;
	int have_rex = 0;
	uint8_t op;

	if (buf == NULL || buflen == 0 || out == NULL)
		return -1;

	memset(out, 0, sizeof(*out));
	out->addr = addr;

	/* REX prefix */
	if ((buf[0] & 0xf0) == 0x40) {
		have_rex = 1;
		rex_w = (buf[0] >> 3) & 1;
		rex_r = (buf[0] >> 2) & 1;
		rex_x = (buf[0] >> 1) & 1;
		rex_b = buf[0] & 1;
		pos = 1;
		if (buflen < 2) {
			emit_db(addr, buf, out);
			return 0;
		}
	}
	(void)have_rex;

	op = buf[pos];

	/* --- single-byte no-operand --- */
	switch (op) {
	case 0x90:
		if (pos != 0)
			break;
		copy_bytes(out, buf, 1);
		snprintf(out->text, sizeof(out->text), "nop");
		out->kind = ZINSN_NOP;
		return 0;
	case 0xcc:
		if (pos != 0)
			break;
		copy_bytes(out, buf, 1);
		snprintf(out->text, sizeof(out->text), "int3");
		out->kind = ZINSN_INT3;
		return 0;
	case 0xc3:
		if (pos != 0)
			break;
		copy_bytes(out, buf, 1);
		snprintf(out->text, sizeof(out->text), "ret");
		out->kind = ZINSN_RET;
		return 0;
	case 0xc9:
		if (pos != 0)
			break;
		copy_bytes(out, buf, 1);
		snprintf(out->text, sizeof(out->text), "leave");
		out->kind = ZINSN_OTHER;
		return 0;
	default:
		break;
	}

	/* push/pop r64: 50+r / 58+r (with optional REX.B for r8..r15) */
	if (op >= 0x50 && op <= 0x5f) {
		int r = (op - 0x50) & 7;
		int ispop = (op >= 0x58);
		int reg = r | (rex_b ? 8 : 0);
		copy_bytes(out, buf, pos + 1);
		snprintf(out->text, sizeof(out->text), "%s %s",
		    ispop ? "pop" : "push", reg64[reg]);
		out->kind = ispop ? ZINSN_POP : ZINSN_PUSH;
		return 0;
	}

	/* jmp8 / jcc rel8 (no REX) */
	if (pos == 0 && op == 0xeb) {
		if (buflen < 2) { emit_db(addr, buf, out); return 0; }
		copy_bytes(out, buf, 2);
		out->kind = ZINSN_JMP;
		out->is_branch = 1;
		out->has_target = 1;
		out->target = addr + 2 + (int8_t)buf[1];
		snprintf(out->text, sizeof(out->text), "jmp8 0x%llx",
		    (unsigned long long)out->target);
		return 0;
	}
	if (pos == 0 && op >= 0x70 && op <= 0x7f) {
		if (buflen < 2) { emit_db(addr, buf, out); return 0; }
		copy_bytes(out, buf, 2);
		out->kind = ZINSN_JCC;
		out->is_branch = 1;
		out->is_cond = 1;
		out->has_target = 1;
		out->target = addr + 2 + (int8_t)buf[1];
		snprintf(out->text, sizeof(out->text), "%s8 0x%llx",
		    jcc_name(op), (unsigned long long)out->target);
		return 0;
	}

	/* jmp rel32 / call rel32 */
	if (pos == 0 && op == 0xe9) {
		if (buflen < 5) { emit_db(addr, buf, out); return 0; }
		copy_bytes(out, buf, 5);
		out->kind = ZINSN_JMP;
		out->is_branch = 1;
		out->has_target = 1;
		out->target = addr + 5 + read_rel32(buf + 1);
		snprintf(out->text, sizeof(out->text), "jmp 0x%llx",
		    (unsigned long long)out->target);
		return 0;
	}
	if (pos == 0 && op == 0xe8) {
		if (buflen < 5) { emit_db(addr, buf, out); return 0; }
		copy_bytes(out, buf, 5);
		out->kind = ZINSN_CALL;
		out->is_call = 1;
		out->has_target = 1;
		out->target = addr + 5 + read_rel32(buf + 1);
		snprintf(out->text, sizeof(out->text), "call 0x%llx",
		    (unsigned long long)out->target);
		return 0;
	}

	/* 0f xx: near jcc */
	if (pos == 0 && op == 0x0f) {
		if (buflen < 2) { emit_db(addr, buf, out); return 0; }
		if (buf[1] >= 0x80 && buf[1] <= 0x8f) {
			if (buflen < 6) {
				emit_db(addr, buf, out);
				return 0;
			}
			copy_bytes(out, buf, 6);
			out->kind = ZINSN_JCC;
			out->is_branch = 1;
			out->is_cond = 1;
			out->has_target = 1;
			out->target = addr + 6 + read_rel32(buf + 2);
			snprintf(out->text, sizeof(out->text), "%s 0x%llx",
			    jcc_name(buf[1]),
			    (unsigned long long)out->target);
			return 0;
		}
		emit_db(addr, buf, out);
		return 0;
	}

	/* FF /2 call r/m64, FF /4 jmp r/m64 - register form only.
	 * In long mode FF /2 and FF /4 are implicitly 64-bit; REX.W
	 * is not required.  We only decode mod=3 here so that
	 * `41 FF E3` -> `jmp r11` and `41 FF D3` -> `call r11`. */
	if (op == 0xff) {
		uint8_t modrm;
		int sub;
		int rm;
		size_t mpos = pos + 1;
		if (buflen < mpos + 1) {
			emit_db(addr, buf, out); return 0;
		}
		modrm = buf[mpos];
		if (((modrm >> 6) & 3) == 3) {
			sub = (modrm >> 3) & 7;
			rm = (modrm & 7) | (rex_b ? 8 : 0);
			if (sub == 4) {
				copy_bytes(out, buf, mpos + 1);
				out->kind = ZINSN_JMP;
				out->is_branch = 1;
				snprintf(out->text, sizeof(out->text),
				    "jmp %s", reg64[rm]);
				return 0;
			}
			if (sub == 2) {
				copy_bytes(out, buf, mpos + 1);
				out->kind = ZINSN_CALL;
				out->is_call = 1;
				snprintf(out->text, sizeof(out->text),
				    "call %s", reg64[rm]);
				return 0;
			}
		}
		emit_db(addr, buf, out);
		return 0;
	}

	/* mov r32/r64, imm: b8+rd */
	if (op >= 0xb8 && op <= 0xbf) {
		int r = (op - 0xb8) & 7;
		int reg = r | (rex_b ? 8 : 0);
		if (rex_w) {
			if (buflen < pos + 1 + 8) {
				emit_db(addr, buf, out); return 0;
			}
			copy_bytes(out, buf, pos + 1 + 8);
			out->kind = ZINSN_MOV;
			snprintf(out->text, sizeof(out->text),
			    "mov %s, 0x%llx", reg64[reg],
			    (unsigned long long)read_imm64(buf + pos + 1));
			return 0;
		}
		if (buflen < pos + 1 + 4) {
			emit_db(addr, buf, out); return 0;
		}
		copy_bytes(out, buf, pos + 1 + 4);
		out->kind = ZINSN_MOV;
		snprintf(out->text, sizeof(out->text), "mov %s, 0x%lx",
		    reg32[reg],
		    (unsigned long)(uint32_t)read_rel32(buf + pos + 1));
		return 0;
	}

	/* opcodes using ModRM: 89, 8b, 8d, 31, 85, 39, 83, 81 */
	if (op == 0x89 || op == 0x8b || op == 0x8d ||
	    op == 0x31 || op == 0x85 || op == 0x39 ||
	    op == 0x83 || op == 0x81) {
		uint8_t modrm;
		int mod, reg_field, rm;
		size_t mpos = pos + 1; /* index of modrm */
		size_t extra;
		int want_64 = rex_w;
		const char **rtab;
		const char *dst_name, *src_name;
		char opbuf[32];
		int rip_rel = 0;
		int32_t rip_disp = 0;

		if (buflen < mpos + 1) {
			emit_db(addr, buf, out); return 0;
		}
		modrm = buf[mpos];
		mod = (modrm >> 6) & 3;
		reg_field = ((modrm >> 3) & 7) | (rex_r ? 8 : 0);
		rm = (modrm & 7) | (rex_b ? 8 : 0);
		rtab = want_64 ? reg64 : reg32;

		/* ALU immediate group (83 /n imm8, 81 /n imm32):
		 * /0 ADD, /5 SUB, /7 CMP; only mod=3 supported. */
		if (op == 0x83 || op == 0x81) {
			int sub = (modrm >> 3) & 7; /* without REX.R */
			const char *mn = NULL;
			enum zinsn_kind kind = ZINSN_OTHER;
			switch (sub) {
			case 0: mn = "add"; kind = ZINSN_ADD; break;
			case 5: mn = "sub"; kind = ZINSN_SUB; break;
			case 7: mn = "cmp"; kind = ZINSN_CMP; break;
			default: break;
			}
			if (mn == NULL || mod != 3) {
				emit_db(addr, buf, out); return 0;
			}
			if (op == 0x83) {
				int8_t imm;
				if (buflen < mpos + 2) {
					emit_db(addr, buf, out); return 0;
				}
				imm = (int8_t)buf[mpos + 1];
				copy_bytes(out, buf, mpos + 2);
				out->kind = kind;
				if (imm < 0)
					snprintf(out->text,
					    sizeof(out->text),
					    "%s %s, -0x%x", mn, rtab[rm],
					    (unsigned)(-imm));
				else
					snprintf(out->text,
					    sizeof(out->text),
					    "%s %s, 0x%x", mn, rtab[rm],
					    (unsigned)imm);
				return 0;
			}
			/* 0x81 imm32 */
			{
				int32_t imm;
				if (buflen < mpos + 5) {
					emit_db(addr, buf, out); return 0;
				}
				imm = read_rel32(buf + mpos + 1);
				copy_bytes(out, buf, mpos + 5);
				out->kind = kind;
				snprintf(out->text, sizeof(out->text),
				    "%s %s, 0x%lx", mn, rtab[rm],
				    (unsigned long)(uint32_t)imm);
				return 0;
			}
		}

		/* Determine memory operand (if any) and total length. */
		{
			size_t insn_len;
			extra = 0;
			if (mod == 3) {
				snprintf(opbuf, sizeof(opbuf), "%s",
				    rtab[rm]);
				insn_len = mpos + 1;
			} else {
				int r = decode_modrm_mem(modrm,
				    buf + mpos + 1, buflen - (mpos + 1),
				    rex_b, rex_x, opbuf, sizeof(opbuf),
				    &rip_rel, &rip_disp);
				if (r < 0) {
					emit_db(addr, buf, out); return 0;
				}
				extra = (size_t)r;
				insn_len = mpos + 1 + extra;
				if (rip_rel) {
					zaddr_t t = addr + insn_len +
					    rip_disp;
					snprintf(opbuf, sizeof(opbuf),
					    "[0x%llx]",
					    (unsigned long long)t);
				}
			}

			copy_bytes(out, buf, insn_len);

			if (op == 0x89) {
				/* mov r/m, r -> dst=opbuf, src=reg */
				dst_name = opbuf;
				src_name = rtab[reg_field];
				out->kind = ZINSN_MOV;
				snprintf(out->text, sizeof(out->text),
				    "mov %s, %s", dst_name, src_name);
				return 0;
			}
			if (op == 0x8b) {
				/* mov r, r/m -> dst=reg, src=opbuf */
				dst_name = rtab[reg_field];
				src_name = opbuf;
				out->kind = ZINSN_MOV;
				snprintf(out->text, sizeof(out->text),
				    "mov %s, %s", dst_name, src_name);
				return 0;
			}
			if (op == 0x8d) {
				/* lea r, m - requires mod != 3 */
				if (mod == 3) {
					emit_db(addr, buf, out); return 0;
				}
				dst_name = rtab[reg_field];
				out->kind = ZINSN_LEA;
				if (rip_rel) {
					zaddr_t t = addr + insn_len +
					    rip_disp;
					out->has_target = 1;
					out->target = t;
				}
				snprintf(out->text, sizeof(out->text),
				    "lea %s, %s", dst_name, opbuf);
				return 0;
			}
			if (op == 0x31) {
				dst_name = opbuf;
				src_name = rtab[reg_field];
				out->kind = ZINSN_XOR;
				snprintf(out->text, sizeof(out->text),
				    "xor %s, %s", dst_name, src_name);
				return 0;
			}
			if (op == 0x85) {
				dst_name = opbuf;
				src_name = rtab[reg_field];
				out->kind = ZINSN_TEST;
				snprintf(out->text, sizeof(out->text),
				    "test %s, %s", dst_name, src_name);
				return 0;
			}
			if (op == 0x39) {
				dst_name = opbuf;
				src_name = rtab[reg_field];
				out->kind = ZINSN_CMP;
				snprintf(out->text, sizeof(out->text),
				    "cmp %s, %s", dst_name, src_name);
				return 0;
			}
		}
	}

	/* Unknown: emit db 0xNN for the first byte of the instruction
	 * stream (which may be the REX prefix). */
	emit_db(addr, buf, out);
	return 0;
}

void
ztinydis_print(const struct ztinydis *d)
{
	size_t i;
	char hex[64];
	size_t pos = 0;

	if (d == NULL)
		return;
	hex[0] = 0;
	for (i = 0; i < d->len && pos + 3 < sizeof(hex); i++) {
		pos += (size_t)snprintf(hex + pos, sizeof(hex) - pos, "%02x ",
		    d->bytes[i]);
	}
	printf("%016llx  %-20s  %s\n",
	    (unsigned long long)d->addr, hex, d->text);
}

zaddr_t
ztinydis_fallthrough(const struct ztinydis *d)
{
	if (d == NULL || d->len == 0)
		return 0;
	return d->addr + (zaddr_t)d->len;
}
