/*
 * test_aarch64_dis.c - tests for the AArch64 phase-1 decoder.
 *
 * Pure decoder tests: no target, no ptrace.  Run on every host.
 * Verifies known-good encodings decode to the expected mnemonics
 * and metadata, that unknown encodings fall back to `.word`, and
 * that a short input buffer is reported as a hard error.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg.h"
#include "zdbg_arch.h"
#include "zdbg_arch_aarch64.h"

#define CHECK(cond) \
	do { if (!(cond)) { printf("FAIL: %s:%d %s\n", __FILE__, \
	    __LINE__, #cond); return 1; } } while (0)

/* Pack a 32-bit AArch64 instruction word into a little-endian
 * byte buffer that the decoder consumes. */
static void
pack_le(uint32_t insn, uint8_t buf[4])
{
	buf[0] = (uint8_t)(insn);
	buf[1] = (uint8_t)(insn >> 8);
	buf[2] = (uint8_t)(insn >> 16);
	buf[3] = (uint8_t)(insn >> 24);
}

static int
decode(uint32_t insn, zaddr_t addr, struct zdecode *out)
{
	uint8_t buf[4];

	pack_le(insn, buf);
	memset(out, 0, sizeof(*out));
	return zaarch64_decode_one(addr, buf, sizeof(buf), out);
}

static int
test_basics(void)
{
	struct zdecode d;

	/* nop */
	CHECK(decode(0xd503201fu, 0x1000, &d) == 0);
	CHECK(d.len == 4);
	CHECK(d.kind == ZINSN_NOP);
	CHECK(strcmp(d.text, "nop") == 0);
	CHECK(zaarch64_fallthrough(&d) == 0x1004);

	/* ret (x30 default) */
	CHECK(decode(0xd65f03c0u, 0x2000, &d) == 0);
	CHECK(d.kind == ZINSN_RET);
	CHECK(d.is_branch == 1);
	CHECK(strcmp(d.text, "ret") == 0);

	/* ret x19 */
	CHECK(decode(0xd65f0260u, 0x2000, &d) == 0);
	CHECK(d.kind == ZINSN_RET);
	CHECK(strcmp(d.text, "ret x19") == 0);

	/* brk #0 */
	CHECK(decode(0xd4200000u, 0x3000, &d) == 0);
	CHECK(d.kind == ZINSN_BREAKPOINT);
	CHECK(strstr(d.text, "brk") != NULL);
	CHECK(strstr(d.text, "#0") != NULL);

	/* brk #7 */
	CHECK(decode(0xd42000e0u, 0x3000, &d) == 0);
	CHECK(d.kind == ZINSN_BREAKPOINT);
	CHECK(strstr(d.text, "#7") != NULL);

	/* svc #0 */
	CHECK(decode(0xd4000001u, 0x3000, &d) == 0);
	CHECK(strstr(d.text, "svc") != NULL);
	return 0;
}

static int
test_branch_imm(void)
{
	struct zdecode d;

	/* b +8: imm26 = 2 */
	CHECK(decode(0x14000002u, 0x1000, &d) == 0);
	CHECK(d.kind == ZINSN_JMP);
	CHECK(d.is_branch == 1);
	CHECK(d.is_call == 0);
	CHECK(d.is_cond == 0);
	CHECK(d.has_target == 1);
	CHECK(d.target == 0x1008);

	/* bl +8: imm26 = 2 */
	CHECK(decode(0x94000002u, 0x1000, &d) == 0);
	CHECK(d.kind == ZINSN_CALL);
	CHECK(d.is_branch == 1);
	CHECK(d.is_call == 1);
	CHECK(d.has_target == 1);
	CHECK(d.target == 0x1008);

	/* b -4 (loop to self - 1 instr): imm26 = 0x3ffffff */
	CHECK(decode(0x17ffffffu, 0x2000, &d) == 0);
	CHECK(d.target == 0x1ffc);
	return 0;
}

static int
test_bcond(void)
{
	struct zdecode d;

	/* b.eq +8: cond=0, imm19=2 -> insn = 0x54000040 */
	CHECK(decode(0x54000040u, 0x1000, &d) == 0);
	CHECK(d.kind == ZINSN_JCC);
	CHECK(d.is_cond == 1);
	CHECK(d.has_target == 1);
	CHECK(d.target == 0x1008);
	CHECK(strncmp(d.text, "b.eq", 4) == 0);

	/* b.ne +8 */
	CHECK(decode(0x54000041u, 0x1000, &d) == 0);
	CHECK(strncmp(d.text, "b.ne", 4) == 0);

	/* b.lt +8: cond=11 */
	CHECK(decode(0x5400004bu, 0x1000, &d) == 0);
	CHECK(strncmp(d.text, "b.lt", 4) == 0);
	return 0;
}

static int
test_cb_tb(void)
{
	struct zdecode d;

	/* cbz x0, +8: 0xb4000040 */
	CHECK(decode(0xb4000040u, 0x1000, &d) == 0);
	CHECK(d.kind == ZINSN_JCC);
	CHECK(d.is_cond == 1);
	CHECK(d.has_target == 1);
	CHECK(d.target == 0x1008);
	CHECK(strstr(d.text, "cbz") != NULL);
	CHECK(strstr(d.text, "x0") != NULL);

	/* cbnz w1, +8: 0x35000041 */
	CHECK(decode(0x35000041u, 0x1000, &d) == 0);
	CHECK(d.kind == ZINSN_JCC);
	CHECK(d.target == 0x1008);
	CHECK(strstr(d.text, "cbnz") != NULL);
	CHECK(strstr(d.text, "w1") != NULL);

	/* tbz w2, #0, +8: b5=0, b40=0, imm14=2, rt=2 -> 0x36000042 */
	CHECK(decode(0x36000042u, 0x1000, &d) == 0);
	CHECK(d.kind == ZINSN_JCC);
	CHECK(d.target == 0x1008);
	CHECK(strstr(d.text, "tbz") != NULL);
	CHECK(strstr(d.text, "#0") != NULL);

	/* tbnz w2, #0, +8: 0x37000042 */
	CHECK(decode(0x37000042u, 0x1000, &d) == 0);
	CHECK(strstr(d.text, "tbnz") != NULL);

	/* tbnz x19, #63, +4: b5=1, b40=0x1f, imm14=1, rt=19 ->
	 * insn = 0xb7f80033 */
	CHECK(decode(0xb7f80033u, 0x2000, &d) == 0);
	CHECK(strstr(d.text, "tbnz") != NULL);
	CHECK(strstr(d.text, "x19") != NULL);
	CHECK(strstr(d.text, "#63") != NULL);
	CHECK(d.target == 0x2004);
	return 0;
}

static int
test_branch_reg(void)
{
	struct zdecode d;

	/* br x16: 0xd61f0200 */
	CHECK(decode(0xd61f0200u, 0x1000, &d) == 0);
	CHECK(d.kind == ZINSN_JMP);
	CHECK(d.is_branch == 1);
	CHECK(d.is_call == 0);
	CHECK(d.has_target == 0);
	CHECK(strcmp(d.text, "br x16") == 0);

	/* blr x17: 0xd63f0220 */
	CHECK(decode(0xd63f0220u, 0x1000, &d) == 0);
	CHECK(d.kind == ZINSN_CALL);
	CHECK(d.is_call == 1);
	CHECK(d.is_branch == 1);
	CHECK(d.has_target == 0);
	CHECK(strcmp(d.text, "blr x17") == 0);
	CHECK(zaarch64_fallthrough(&d) == 0x1004);
	return 0;
}

static int
test_adr_adrp(void)
{
	struct zdecode d;

	/* adr x0, +0: insn=0x10000000 */
	CHECK(decode(0x10000000u, 0x1000, &d) == 0);
	CHECK(d.kind == ZINSN_LEA);
	CHECK(d.has_target == 1);
	CHECK(d.target == 0x1000);
	CHECK(strstr(d.text, "adr ") != NULL);
	CHECK(strstr(d.text, "x0") != NULL);

	/* adr x0, +4: immlo=0, immhi=1 -> insn=0x10000020 */
	CHECK(decode(0x10000020u, 0x1000, &d) == 0);
	CHECK(d.target == 0x1004);

	/* adrp x0, page at pc&~0xfff + (1<<12) = 0x2000:
	 * op=1, immlo=1, immhi=0 -> 0xb0000000 */
	CHECK(decode(0xb0000000u, 0x1000, &d) == 0);
	CHECK(d.kind == ZINSN_LEA);
	CHECK(d.target == 0x2000);
	CHECK(strstr(d.text, "adrp") != NULL);
	return 0;
}

static int
test_ldp_stp(void)
{
	struct zdecode d;

	/* stp x29, x30, [sp, #-16]! : 0xa9bf7bfd */
	CHECK(decode(0xa9bf7bfdu, 0x1000, &d) == 0);
	CHECK(d.len == 4);
	CHECK(strstr(d.text, "stp") != NULL);
	CHECK(strstr(d.text, "x29") != NULL);
	CHECK(strstr(d.text, "x30") != NULL);
	CHECK(strstr(d.text, "[sp, #-16]!") != NULL);

	/* ldp x29, x30, [sp], #16 : 0xa8c17bfd */
	CHECK(decode(0xa8c17bfdu, 0x1000, &d) == 0);
	CHECK(strstr(d.text, "ldp") != NULL);
	CHECK(strstr(d.text, "[sp], #16") != NULL);
	return 0;
}

static int
test_addsub_imm(void)
{
	struct zdecode d;

	/* mov x29, sp = add x29, sp, #0 : 0x910003fd */
	CHECK(decode(0x910003fdu, 0x1000, &d) == 0);
	/* Either "mov x29, sp" alias or "add x29, sp, #0" is OK,
	 * but our decoder emits the alias. */
	CHECK(strstr(d.text, "mov") != NULL);
	CHECK(strstr(d.text, "x29") != NULL);
	CHECK(strstr(d.text, "sp") != NULL);
	CHECK(d.kind == ZINSN_MOV);

	/* add x0, x1, #4 : sf=1 op=0 S=0 sh=0 imm12=4 rn=1 rd=0
	 * -> 0x91001020 */
	CHECK(decode(0x91001020u, 0x1000, &d) == 0);
	CHECK(d.kind == ZINSN_ADD);
	CHECK(strstr(d.text, "add") != NULL);
	CHECK(strstr(d.text, "#4") != NULL);

	/* sub x0, x1, #4 : op=1 -> 0xd1001020 */
	CHECK(decode(0xd1001020u, 0x1000, &d) == 0);
	CHECK(d.kind == ZINSN_SUB);
	CHECK(strstr(d.text, "sub") != NULL);

	/* cmp x1, #0 : SUBS Rd=ZR -> 0xf100003f */
	CHECK(decode(0xf100003fu, 0x1000, &d) == 0);
	CHECK(d.kind == ZINSN_CMP);
	CHECK(strstr(d.text, "cmp") != NULL);
	return 0;
}

static int
test_unknown_and_short(void)
{
	struct zdecode d;
	uint8_t short_buf[2] = { 0x00, 0x00 };

	/* All-zero word is not in our recognized set; should
	 * fall back to .word. */
	CHECK(decode(0x00000000u, 0x1000, &d) == 0);
	CHECK(d.len == 4);
	CHECK(d.kind == ZINSN_OTHER);
	CHECK(strstr(d.text, ".word") != NULL);
	CHECK(strstr(d.text, "0x00000000") != NULL);

	/* Some clearly-bogus bits -> .word. */
	CHECK(decode(0x12345678u, 0x1000, &d) == 0);
	CHECK(d.kind == ZINSN_OTHER);
	CHECK(strstr(d.text, "0x12345678") != NULL);

	/* Short buffer must hard-fail. */
	memset(&d, 0, sizeof(d));
	CHECK(zaarch64_decode_one(0x1000, short_buf,
	    sizeof(short_buf), &d) == -1);

	/* NULL out is a hard error. */
	CHECK(zaarch64_decode_one(0x1000, short_buf, 4, NULL) == -1);
	return 0;
}

static int
test_fallthrough_edges(void)
{
	struct zdecode d;

	/* fallthrough(NULL) and zero-length report 0. */
	CHECK(zaarch64_fallthrough(NULL) == 0);
	memset(&d, 0, sizeof(d));
	d.addr = 0x1000;
	d.len = 0;
	CHECK(zaarch64_fallthrough(&d) == 0);
	return 0;
}

int
main(void)
{
	if (test_basics()) return 1;
	if (test_branch_imm()) return 1;
	if (test_bcond()) return 1;
	if (test_cb_tb()) return 1;
	if (test_branch_reg()) return 1;
	if (test_adr_adrp()) return 1;
	if (test_ldp_stp()) return 1;
	if (test_addsub_imm()) return 1;
	if (test_unknown_and_short()) return 1;
	if (test_fallthrough_edges()) return 1;
	printf("test_aarch64_dis ok\n");
	return 0;
}
