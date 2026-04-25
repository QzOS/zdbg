/*
 * test_tinydis.c - tests for the tiny disassembler.
 */

#include <stdio.h>
#include <string.h>

#include "zdbg_tinyasm.h"
#include "zdbg_tinydis.h"

static int failures;

#define CHECK(cond) do {                                              \
	if (!(cond)) {                                                \
		fprintf(stderr, "FAIL %s:%d: %s\n",                   \
		    __FILE__, __LINE__, #cond);                       \
		failures++;                                           \
	}                                                             \
} while (0)

static int
decode(zaddr_t addr, const uint8_t *bytes, size_t n, struct ztinydis *d)
{
	return ztinydis_one(addr, bytes, n, d);
}

static void
test_fixed(void)
{
	struct ztinydis d;
	uint8_t buf[16];

	buf[0] = 0x90;
	CHECK(decode(0x400000, buf, 1, &d) == 0);
	CHECK(d.len == 1);
	CHECK(strcmp(d.text, "nop") == 0);
	CHECK(d.kind == ZINSN_NOP);

	buf[0] = 0xcc;
	CHECK(decode(0x400000, buf, 1, &d) == 0);
	CHECK(strcmp(d.text, "int3") == 0);
	CHECK(d.kind == ZINSN_INT3);

	buf[0] = 0xc3;
	CHECK(decode(0x400000, buf, 1, &d) == 0);
	CHECK(strcmp(d.text, "ret") == 0);
	CHECK(d.kind == ZINSN_RET);

	buf[0] = 0xc9;
	CHECK(decode(0x400000, buf, 1, &d) == 0);
	CHECK(strcmp(d.text, "leave") == 0);
}

static void
test_push_pop(void)
{
	struct ztinydis d;
	uint8_t buf[4];

	buf[0] = 0x55; /* push rbp */
	CHECK(decode(0x1000, buf, 1, &d) == 0);
	CHECK(d.len == 1);
	CHECK(strcmp(d.text, "push rbp") == 0);
	CHECK(d.kind == ZINSN_PUSH);

	buf[0] = 0x5d; /* pop rbp */
	CHECK(decode(0x1000, buf, 1, &d) == 0);
	CHECK(strcmp(d.text, "pop rbp") == 0);
	CHECK(d.kind == ZINSN_POP);

	buf[0] = 0x53; /* push rbx */
	CHECK(decode(0x1000, buf, 1, &d) == 0);
	CHECK(strcmp(d.text, "push rbx") == 0);

	/* push r12 = 41 54 */
	buf[0] = 0x41;
	buf[1] = 0x54;
	CHECK(decode(0x1000, buf, 2, &d) == 0);
	CHECK(d.len == 2);
	CHECK(strcmp(d.text, "push r12") == 0);
}

static void
test_mov_reg_reg(void)
{
	struct ztinydis d;
	uint8_t buf[4];

	/* mov rbp, rsp: 48 89 e5 */
	buf[0] = 0x48; buf[1] = 0x89; buf[2] = 0xe5;
	CHECK(decode(0x1000, buf, 3, &d) == 0);
	CHECK(d.len == 3);
	CHECK(strcmp(d.text, "mov rbp, rsp") == 0);
	CHECK(d.kind == ZINSN_MOV);

	/* mov rax, rbx: 48 89 d8 (89 /r: r/m=rax reg=rbx) */
	buf[0] = 0x48; buf[1] = 0x89; buf[2] = 0xd8;
	CHECK(decode(0x1000, buf, 3, &d) == 0);
	CHECK(strcmp(d.text, "mov rax, rbx") == 0);

	/* mov eax, ebx: 89 d8 */
	buf[0] = 0x89; buf[1] = 0xd8;
	CHECK(decode(0x1000, buf, 2, &d) == 0);
	CHECK(d.len == 2);
	CHECK(strcmp(d.text, "mov eax, ebx") == 0);
}

static void
test_stack_adjust(void)
{
	struct ztinydis d;
	uint8_t buf[8];

	/* sub rsp, 0x10 : 48 83 ec 10 */
	buf[0] = 0x48; buf[1] = 0x83; buf[2] = 0xec; buf[3] = 0x10;
	CHECK(decode(0x1000, buf, 4, &d) == 0);
	CHECK(d.len == 4);
	CHECK(strcmp(d.text, "sub rsp, 0x10") == 0);
	CHECK(d.kind == ZINSN_SUB);

	/* add rsp, 0x20 : 48 83 c4 20 */
	buf[0] = 0x48; buf[1] = 0x83; buf[2] = 0xc4; buf[3] = 0x20;
	CHECK(decode(0x1000, buf, 4, &d) == 0);
	CHECK(strcmp(d.text, "add rsp, 0x20") == 0);
	CHECK(d.kind == ZINSN_ADD);

	/* sub rsp, 0x1000 : 48 81 ec 00 10 00 00 */
	buf[0] = 0x48; buf[1] = 0x81; buf[2] = 0xec;
	buf[3] = 0x00; buf[4] = 0x10; buf[5] = 0x00; buf[6] = 0x00;
	CHECK(decode(0x1000, buf, 7, &d) == 0);
	CHECK(d.len == 7);
	CHECK(strcmp(d.text, "sub rsp, 0x1000") == 0);
}

static void
test_call_jmp(void)
{
	struct ztinydis d;
	uint8_t buf[8];

	/* call 0x1005 : e8 00 00 00 00 at 0x1000 */
	buf[0] = 0xe8; buf[1] = 0; buf[2] = 0; buf[3] = 0; buf[4] = 0;
	CHECK(decode(0x1000, buf, 5, &d) == 0);
	CHECK(d.len == 5);
	CHECK(d.kind == ZINSN_CALL);
	CHECK(d.is_call == 1);
	CHECK(d.has_target == 1);
	CHECK(d.target == 0x1005);
	CHECK(ztinydis_fallthrough(&d) == 0x1005);
	CHECK(strstr(d.text, "call") != NULL);
	CHECK(strstr(d.text, "1005") != NULL);

	/* jmp 0x1080 : e9 7b 00 00 00 at 0x1000 */
	buf[0] = 0xe9; buf[1] = 0x7b; buf[2] = 0; buf[3] = 0; buf[4] = 0;
	CHECK(decode(0x1000, buf, 5, &d) == 0);
	CHECK(d.kind == ZINSN_JMP);
	CHECK(d.is_branch == 1);
	CHECK(d.target == 0x1080);
}

static void
test_jcc(void)
{
	struct ztinydis d;
	uint8_t buf[8];

	/* jl8 0x1010 : 7c 0e at 0x1000 */
	buf[0] = 0x7c; buf[1] = 0x0e;
	CHECK(decode(0x1000, buf, 2, &d) == 0);
	CHECK(d.len == 2);
	CHECK(d.kind == ZINSN_JCC);
	CHECK(d.is_cond == 1);
	CHECK(d.target == 0x1010);
	CHECK(strstr(d.text, "jl8") != NULL);

	/* jge near: 0f 8d 04 00 00 00 at 0x1000 -> target 0x100a */
	buf[0] = 0x0f; buf[1] = 0x8d; buf[2] = 0x04;
	buf[3] = 0; buf[4] = 0; buf[5] = 0;
	CHECK(decode(0x1000, buf, 6, &d) == 0);
	CHECK(d.len == 6);
	CHECK(d.kind == ZINSN_JCC);
	CHECK(d.target == 0x100a);
	CHECK(strstr(d.text, "jge") != NULL);
}

static void
test_lea_rip(void)
{
	struct ztinydis d;
	uint8_t buf[8];

	/* lea rax, [rip+0x10] at 0x1000 -> target = 0x1000+7+0x10 = 0x1017 */
	buf[0] = 0x48; buf[1] = 0x8d; buf[2] = 0x05;
	buf[3] = 0x10; buf[4] = 0; buf[5] = 0; buf[6] = 0;
	CHECK(decode(0x1000, buf, 7, &d) == 0);
	CHECK(d.len == 7);
	CHECK(d.kind == ZINSN_LEA);
	CHECK(d.has_target == 1);
	CHECK(d.target == 0x1017);
	CHECK(strstr(d.text, "lea rax") != NULL);
	CHECK(strstr(d.text, "1017") != NULL);
}

static void
test_imm_mov(void)
{
	struct ztinydis d;
	uint8_t buf[16];

	/* mov eax, 0x12345678 : b8 78 56 34 12 */
	buf[0] = 0xb8;
	buf[1] = 0x78; buf[2] = 0x56; buf[3] = 0x34; buf[4] = 0x12;
	CHECK(decode(0x1000, buf, 5, &d) == 0);
	CHECK(d.len == 5);
	CHECK(d.kind == ZINSN_MOV);
	CHECK(strstr(d.text, "mov eax") != NULL);
	CHECK(strstr(d.text, "12345678") != NULL);

	/* mov rax, 0x1122334455667788 : 48 b8 .. */
	buf[0] = 0x48; buf[1] = 0xb8;
	buf[2] = 0x88; buf[3] = 0x77; buf[4] = 0x66; buf[5] = 0x55;
	buf[6] = 0x44; buf[7] = 0x33; buf[8] = 0x22; buf[9] = 0x11;
	CHECK(decode(0x1000, buf, 10, &d) == 0);
	CHECK(d.len == 10);
	CHECK(strstr(d.text, "mov rax") != NULL);
	CHECK(strstr(d.text, "1122334455667788") != NULL);
}

static void
test_alu_simple(void)
{
	struct ztinydis d;
	uint8_t buf[8];

	/* xor eax, eax : 31 c0 */
	buf[0] = 0x31; buf[1] = 0xc0;
	CHECK(decode(0x1000, buf, 2, &d) == 0);
	CHECK(d.len == 2);
	CHECK(d.kind == ZINSN_XOR);
	CHECK(strcmp(d.text, "xor eax, eax") == 0);

	/* test eax, eax : 85 c0 */
	buf[0] = 0x85; buf[1] = 0xc0;
	CHECK(decode(0x1000, buf, 2, &d) == 0);
	CHECK(d.kind == ZINSN_TEST);
	CHECK(strcmp(d.text, "test eax, eax") == 0);

	/* cmp eax, 0x10 : 83 f8 10 */
	buf[0] = 0x83; buf[1] = 0xf8; buf[2] = 0x10;
	CHECK(decode(0x1000, buf, 3, &d) == 0);
	CHECK(d.len == 3);
	CHECK(d.kind == ZINSN_CMP);
	CHECK(strcmp(d.text, "cmp eax, 0x10") == 0);
}

static void
test_unknown(void)
{
	struct ztinydis d;
	uint8_t buf[1];
	/* 0x06 is an invalid opcode in 64-bit mode (was push ES in 32-bit). */
	buf[0] = 0x06;
	CHECK(decode(0x400000, buf, 1, &d) == 0);
	CHECK(d.len == 1);
	CHECK(strcmp(d.text, "db 0x06") == 0);
}

static void
test_roundtrip(void)
{
	struct ztinyasm enc;
	struct ztinydis d;

	/* jmp rel32 */
	CHECK(ztinyasm_assemble(0x401000, "jmp 0x401080", &enc, NULL) == 0);
	CHECK(ztinydis_one(0x401000, enc.code, enc.len, &d) == 0);
	CHECK(d.len == 5);
	CHECK(strstr(d.text, "jmp") != NULL);
	CHECK(strstr(d.text, "401080") != NULL);

	/* jmp8 */
	CHECK(ztinyasm_assemble(0x401000, "jmp8 0x401010", &enc, NULL) == 0);
	CHECK(ztinydis_one(0x401000, enc.code, enc.len, &d) == 0);
	CHECK(d.len == 2);
	CHECK(strstr(d.text, "jmp8") != NULL);
	CHECK(strstr(d.text, "401010") != NULL);

	/* jz rel32 */
	CHECK(ztinyasm_assemble(0x401000, "jz 0x401080", &enc, NULL) == 0);
	CHECK(ztinydis_one(0x401000, enc.code, enc.len, &d) == 0);
	CHECK(d.len == 6);
	CHECK(strstr(d.text, "jz") != NULL);

	/* jnz8 */
	CHECK(ztinyasm_assemble(0x401000, "jnz8 0x401010", &enc, NULL) == 0);
	CHECK(ztinydis_one(0x401000, enc.code, enc.len, &d) == 0);
	CHECK(d.len == 2);
	CHECK(strstr(d.text, "jnz8") != NULL);
}

static void
test_indirect_r11(void)
{
	struct ztinydis d;
	uint8_t buf[16];

	/* jmp r11: 41 FF E3 */
	buf[0] = 0x41; buf[1] = 0xff; buf[2] = 0xe3;
	CHECK(ztinydis_one(0x400000, buf, 3, &d) == 0);
	CHECK(d.len == 3);
	CHECK(strcmp(d.text, "jmp r11") == 0);
	CHECK(d.kind == ZINSN_JMP);
	CHECK(d.is_branch);

	/* call r11: 41 FF D3 */
	buf[0] = 0x41; buf[1] = 0xff; buf[2] = 0xd3;
	CHECK(ztinydis_one(0x400000, buf, 3, &d) == 0);
	CHECK(d.len == 3);
	CHECK(strcmp(d.text, "call r11") == 0);
	CHECK(d.kind == ZINSN_CALL);
	CHECK(d.is_call);

	/* jmp rax (no REX): FF E0 */
	buf[0] = 0xff; buf[1] = 0xe0;
	CHECK(ztinydis_one(0x400000, buf, 2, &d) == 0);
	CHECK(d.len == 2);
	CHECK(strcmp(d.text, "jmp rax") == 0);

	/* movabs r11, imm64: 49 BB <imm64-le>.  Existing B8+rd path
	 * already decodes this; we only spot-check it here. */
	buf[0] = 0x49; buf[1] = 0xbb;
	buf[2] = 0x88; buf[3] = 0x77; buf[4] = 0x66; buf[5] = 0x55;
	buf[6] = 0x44; buf[7] = 0x33; buf[8] = 0x22; buf[9] = 0x11;
	CHECK(ztinydis_one(0x400000, buf, 10, &d) == 0);
	CHECK(d.len == 10);
	CHECK(strstr(d.text, "r11") != NULL);
	CHECK(strstr(d.text, "0x1122334455667788") != NULL);
}

int
main(void)
{
	test_fixed();
	test_push_pop();
	test_mov_reg_reg();
	test_stack_adjust();
	test_call_jmp();
	test_jcc();
	test_lea_rip();
	test_imm_mov();
	test_alu_simple();
	test_unknown();
	test_roundtrip();
	test_indirect_r11();

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("test_tinydis ok\n");
	return 0;
}
