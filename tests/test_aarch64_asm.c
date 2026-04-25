/*
 * test_aarch64_asm.c - tests for the AArch64 phase-1 tiny
 * assembler.  Pure encoder tests: no target, no ptrace.  Run on
 * every host.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "zdbg.h"
#include "zdbg_arch.h"
#include "zdbg_arch_aarch64.h"

#define CHECK(cond) \
	do { if (!(cond)) { printf("FAIL: %s:%d %s\n", __FILE__, \
	    __LINE__, #cond); return 1; } } while (0)

/* Fake resolver: parses pc+N / pc-N, hex/dec literals, and a
 * small symbol table.  Also captures the most recent expression
 * string for resolver tests. */
struct fake_ctx {
	zaddr_t pc;
	char last_expr[256];
};

static int
fake_resolve(void *arg, const char *expr, zaddr_t *out)
{
	struct fake_ctx *ctx = (struct fake_ctx *)arg;
	const char *p = expr;

	while (*p == ' ' || *p == '\t') p++;
	if (ctx) {
		size_t n = strlen(expr);
		if (n >= sizeof(ctx->last_expr))
			n = sizeof(ctx->last_expr) - 1;
		memcpy(ctx->last_expr, expr, n);
		ctx->last_expr[n] = 0;
	}
	if (strncmp(p, "pc", 2) == 0) {
		const char *q = p + 2;
		while (*q == ' ' || *q == '\t') q++;
		if (*q == 0) {
			*out = ctx->pc;
			return 0;
		}
		if (*q == '+' || *q == '-') {
			char sign = *q++;
			while (*q == ' ' || *q == '\t') q++;
			long v = 0;
			int base = 10;
			if (q[0] == '0' && (q[1] == 'x' || q[1] == 'X')) {
				base = 16;
				q += 2;
			}
			while (*q) {
				int d;
				if (*q >= '0' && *q <= '9') d = *q - '0';
				else if (base == 16 && *q >= 'a' && *q <= 'f')
					d = *q - 'a' + 10;
				else if (base == 16 && *q >= 'A' && *q <= 'F')
					d = *q - 'A' + 10;
				else if (*q == ' ' || *q == '\t') break;
				else return -1;
				v = v * base + d;
				q++;
			}
			while (*q == ' ' || *q == '\t') q++;
			if (*q != 0) return -1;
			if (sign == '+')
				*out = ctx->pc + (zaddr_t)v;
			else
				*out = ctx->pc - (zaddr_t)v;
			return 0;
		}
	}
	if (strcmp(expr, "main") == 0) {
		*out = ctx->pc + 0x100;
		return 0;
	}
	if (strcmp(expr, "helper") == 0) {
		*out = ctx->pc + 0x200;
		return 0;
	}
	/* hex literal */
	{
		uint64_t v = 0;
		const char *q = p;
		int base = 10;
		if (q[0] == '0' && (q[1] == 'x' || q[1] == 'X')) {
			base = 16;
			q += 2;
		}
		if (*q == 0) return -1;
		while (*q) {
			int d;
			if (*q >= '0' && *q <= '9') d = *q - '0';
			else if (base == 16 && *q >= 'a' && *q <= 'f')
				d = *q - 'a' + 10;
			else if (base == 16 && *q >= 'A' && *q <= 'F')
				d = *q - 'A' + 10;
			else return -1;
			v = v * base + d;
			q++;
		}
		*out = (zaddr_t)v;
		return 0;
	}
}

static uint32_t
le32(const uint8_t *b)
{
	return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
	    ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static int
asm1(zaddr_t addr, const char *line, uint8_t buf[4],
    struct fake_ctx *ctx)
{
	size_t len = 0;
	char err[128];
	err[0] = 0;
	if (zaarch64_assemble_one(addr, line, buf, 4, &len,
	    fake_resolve, ctx, err, sizeof(err)) < 0) {
		printf("  asm1 failed: '%s' err='%s'\n", line, err);
		return -1;
	}
	if (len != 4) {
		printf("  asm1 bad len=%zu for '%s'\n", len, line);
		return -1;
	}
	return 0;
}

static int
expect_word(zaddr_t addr, const char *line, uint32_t want,
    struct fake_ctx *ctx)
{
	uint8_t buf[4];
	uint32_t got;
	if (asm1(addr, line, buf, ctx) < 0) {
		printf("FAIL: '%s' did not assemble\n", line);
		return 1;
	}
	got = le32(buf);
	if (got != want) {
		printf("FAIL: '%s' got %08x want %08x\n",
		    line, got, want);
		return 1;
	}
	return 0;
}

static int
expect_fail(zaddr_t addr, const char *line, struct fake_ctx *ctx)
{
	uint8_t buf[4];
	size_t len = 0;
	char err[128];
	err[0] = 0;
	if (zaarch64_assemble_one(addr, line, buf, 4, &len,
	    fake_resolve, ctx, err, sizeof(err)) == 0) {
		printf("FAIL: '%s' should have failed\n", line);
		return 1;
	}
	if (err[0] == 0) {
		printf("FAIL: '%s' failed without error message\n", line);
		return 1;
	}
	return 0;
}

static int
test_basic_words(void)
{
	struct fake_ctx ctx;
	int rc = 0;
	memset(&ctx, 0, sizeof(ctx));
	ctx.pc = 0x1000;

	/* nop -> 1f 20 03 d5 = 0xd503201f */
	rc |= expect_word(0x1000, "nop", 0xd503201fu, &ctx);
	/* brk #0 */
	rc |= expect_word(0x1000, "brk #0", 0xd4200000u, &ctx);
	rc |= expect_word(0x1000, "brk 0",  0xd4200000u, &ctx);
	/* brk #1 -> 0xd4200020 */
	rc |= expect_word(0x1000, "brk #1", 0xd4200020u, &ctx);
	/* int3 alias */
	rc |= expect_word(0x1000, "int3", 0xd4200000u, &ctx);
	/* svc #0 -> 0xd4000001 */
	rc |= expect_word(0x1000, "svc #0", 0xd4000001u, &ctx);
	/* ret */
	rc |= expect_word(0x1000, "ret", 0xd65f03c0u, &ctx);
	/* ret x19 -> 0xd65f0260 */
	rc |= expect_word(0x1000, "ret x19", 0xd65f0260u, &ctx);
	/* br x16 -> 0xd61f0200 */
	rc |= expect_word(0x1000, "br x16", 0xd61f0200u, &ctx);
	/* blr x17 -> 0xd63f0220 */
	rc |= expect_word(0x1000, "blr x17", 0xd63f0220u, &ctx);
	return rc;
}

static int
test_branches(void)
{
	struct fake_ctx ctx;
	int rc = 0;
	memset(&ctx, 0, sizeof(ctx));
	ctx.pc = 0x1000;

	/* b pc+8 -> 0x14000002 */
	rc |= expect_word(0x1000, "b pc+8", 0x14000002u, &ctx);
	/* bl pc+8 -> 0x94000002 */
	rc |= expect_word(0x1000, "bl pc+8", 0x94000002u, &ctx);
	/* b.eq pc+8 -> 0x54000040 */
	rc |= expect_word(0x1000, "b.eq pc+8", 0x54000040u, &ctx);
	/* b.ne pc+8 -> 0x54000041 */
	rc |= expect_word(0x1000, "b.ne pc+8", 0x54000041u, &ctx);
	/* aliases */
	rc |= expect_word(0x1000, "beq pc+8", 0x54000040u, &ctx);
	rc |= expect_word(0x1000, "bne pc+8", 0x54000041u, &ctx);
	/* cbz x0, pc+8 -> 0xb4000040 */
	rc |= expect_word(0x1000, "cbz x0, pc+8", 0xb4000040u, &ctx);
	/* cbnz x1, pc+8 -> 0xb5000041 */
	rc |= expect_word(0x1000, "cbnz x1, pc+8", 0xb5000041u, &ctx);
	/* w-form cbz w0, pc+8 -> 0x34000040 */
	rc |= expect_word(0x1000, "cbz w0, pc+8", 0x34000040u, &ctx);
	/* tbz w2, #0, pc+8 -> 0x36000042 */
	rc |= expect_word(0x1000, "tbz w2, #0, pc+8", 0x36000042u, &ctx);
	/* tbnz w2, #0, pc+8 -> 0x37000042 */
	rc |= expect_word(0x1000, "tbnz w2, #0, pc+8", 0x37000042u, &ctx);
	/* tbz x2, #32, pc+8 -> sf bit 31 set */
	rc |= expect_word(0x1000, "tbz x2, #32, pc+8",
	    0xb6000042u, &ctx);

	/* negative offset b.eq pc-4 */
	{
		uint8_t buf[4];
		uint32_t got;
		if (asm1(0x1000, "b.eq pc-4", buf, &ctx) == 0) {
			got = le32(buf);
			/* off=-4, imm19=-1 (signed) -> 0x7ffff in 19 bits */
			uint32_t want = 0x54000000u |
			    (((uint32_t)0x7ffff) << 5) | 0;
			if (got != want) {
				printf("FAIL: b.eq pc-4 got %08x want %08x\n",
				    got, want);
				rc |= 1;
			}
		} else {
			rc |= 1;
		}
	}

	return rc;
}

static int
test_arith(void)
{
	struct fake_ctx ctx;
	int rc = 0;
	memset(&ctx, 0, sizeof(ctx));

	/* add x0, x1, #16 -> 0x91004020 */
	rc |= expect_word(0, "add x0, x1, #16", 0x91004020u, &ctx);
	/* sub x0, x1, #16 -> 0xd1004020 */
	rc |= expect_word(0, "sub x0, x1, #16", 0xd1004020u, &ctx);
	/* cmp x1, #0 -> subs xzr, x1, #0 -> 0xf100003f */
	rc |= expect_word(0, "cmp x1, #0", 0xf100003fu, &ctx);
	/* mov x29, sp -> add x29, sp, #0 -> 0x910003fd */
	rc |= expect_word(0, "mov x29, sp", 0x910003fdu, &ctx);
	/* mov sp, x29 -> add sp, x29, #0 -> 0x910003bf */
	rc |= expect_word(0, "mov sp, x29", 0x910003bfu, &ctx);
	/* shifted add: add x0, x1, #4096 -> sh=1 imm=1 */
	{
		uint32_t want = 0x91000000u | (1u << 22) |
		    (1u << 10) | (1u << 5) | 0u;
		rc |= expect_word(0, "add x0, x1, #4096", want, &ctx);
	}
	/* w-form */
	rc |= expect_word(0, "add w0, w1, #16", 0x11004020u, &ctx);
	return rc;
}

static int
test_negative(void)
{
	struct fake_ctx ctx;
	int rc = 0;
	memset(&ctx, 0, sizeof(ctx));
	ctx.pc = 0x1000;

	/* misaligned branch */
	rc |= expect_fail(0x1000, "b pc+1", &ctx);
	/* b out of range: pc + 0x10000000 -> not representable */
	rc |= expect_fail(0x1000, "b pc+0x10000000", &ctx);
	/* b.eq out of range */
	rc |= expect_fail(0x1000, "b.eq pc+0x100000", &ctx);
	/* cbz out of range */
	rc |= expect_fail(0x1000, "cbz x0, pc+0x100000", &ctx);
	/* tbz w-reg with bit 32 */
	rc |= expect_fail(0x1000, "tbz w0, #32, pc+8", &ctx);
	/* tbz x-reg with bit 64 */
	rc |= expect_fail(0x1000, "tbz x0, #64, pc+8", &ctx);
	/* bad register */
	rc |= expect_fail(0x1000, "ret x99", &ctx);
	rc |= expect_fail(0x1000, "ret x31", &ctx);
	/* br with w-reg */
	rc |= expect_fail(0x1000, "br w0", &ctx);
	/* unknown mnemonic */
	rc |= expect_fail(0x1000, "foo", &ctx);
	/* bad condition */
	rc |= expect_fail(0x1000, "b.zz pc+4", &ctx);
	/* brk imm overflow */
	rc |= expect_fail(0x1000, "brk #65536", &ctx);
	/* add imm out of range */
	rc |= expect_fail(0x1000, "add x0, x1, #0x1001", &ctx);
	/* mov xD, xN (not SP form) */
	rc |= expect_fail(0x1000, "mov x0, x1", &ctx);
	return rc;
}

static int
test_patch(void)
{
	struct fake_ctx ctx;
	uint8_t buf[16];
	size_t len = 0;
	char err[128];
	int rc = 0;
	memset(&ctx, 0, sizeof(ctx));
	ctx.pc = 0x1000;

	/* patch_len 4: single nop */
	memset(buf, 0xaa, sizeof(buf));
	err[0] = 0;
	CHECK(zaarch64_assemble_patch(0x1000, 4, "nop", buf,
	    sizeof(buf), &len, fake_resolve, &ctx, err,
	    sizeof(err)) == 0);
	CHECK(len == 4);
	CHECK(le32(buf) == 0xd503201fu);

	/* patch_len 8: instruction + 1 nop */
	memset(buf, 0xaa, sizeof(buf));
	err[0] = 0;
	CHECK(zaarch64_assemble_patch(0x1000, 8, "ret", buf,
	    sizeof(buf), &len, fake_resolve, &ctx, err,
	    sizeof(err)) == 0);
	CHECK(len == 8);
	CHECK(le32(buf) == 0xd65f03c0u);
	CHECK(le32(buf + 4) == 0xd503201fu);

	/* patch_len 12: b foo + 2 nops */
	memset(buf, 0xaa, sizeof(buf));
	err[0] = 0;
	CHECK(zaarch64_assemble_patch(0x1000, 12, "b pc+8", buf,
	    sizeof(buf), &len, fake_resolve, &ctx, err,
	    sizeof(err)) == 0);
	CHECK(len == 12);
	CHECK(le32(buf) == 0x14000002u);
	CHECK(le32(buf + 4) == 0xd503201fu);
	CHECK(le32(buf + 8) == 0xd503201fu);

	/* reject patch_len 2 */
	err[0] = 0;
	CHECK(zaarch64_assemble_patch(0x1000, 2, "nop", buf,
	    sizeof(buf), &len, fake_resolve, &ctx, err,
	    sizeof(err)) < 0);
	CHECK(err[0] != 0);

	/* reject patch_len 5 */
	err[0] = 0;
	CHECK(zaarch64_assemble_patch(0x1000, 5, "nop", buf,
	    sizeof(buf), &len, fake_resolve, &ctx, err,
	    sizeof(err)) < 0);
	CHECK(err[0] != 0);
	CHECK(strstr(err, "multiple of 4") != NULL);

	return rc;
}

static int
test_resolver(void)
{
	struct fake_ctx ctx;
	uint8_t buf[4];
	size_t len = 0;
	char err[128];
	int rc = 0;
	memset(&ctx, 0, sizeof(ctx));
	ctx.pc = 0x1000;

	/* b main: target = pc + 0x100, off=0x100, imm26=0x40 */
	err[0] = 0;
	CHECK(zaarch64_assemble_one(0x1000, "b main", buf, sizeof(buf),
	    &len, fake_resolve, &ctx, err, sizeof(err)) == 0);
	CHECK(le32(buf) == (0x14000000u | 0x40u));
	CHECK(strcmp(ctx.last_expr, "main") == 0);

	/* bl helper - resolver sees full expression */
	err[0] = 0;
	CHECK(zaarch64_assemble_one(0x1000, "bl helper", buf, sizeof(buf),
	    &len, fake_resolve, &ctx, err, sizeof(err)) == 0);
	CHECK(strcmp(ctx.last_expr, "helper") == 0);

	/* expression with spaces preserved through to resolver */
	{
		struct fake_ctx ctx2;
		memset(&ctx2, 0, sizeof(ctx2));
		ctx2.pc = 0x1000;
		err[0] = 0;
		/* Will fail to resolve, but the resolver must have
		 * received the full expression text. */
		(void)zaarch64_assemble_one(0x1000, "b pc + 8", buf,
		    sizeof(buf), &len, fake_resolve, &ctx2, err,
		    sizeof(err));
		CHECK(strcmp(ctx2.last_expr, "pc + 8") == 0);
	}

	return rc;
}

static int
test_roundtrip(void)
{
	/* Encode a few instructions, then decode them back and
	 * verify the kind/metadata. */
	struct fake_ctx ctx;
	uint8_t buf[4];
	size_t len = 0;
	char err[128];
	struct zdecode d;
	memset(&ctx, 0, sizeof(ctx));
	ctx.pc = 0x1000;

	err[0] = 0;
	CHECK(zaarch64_assemble_one(0x1000, "b pc+8", buf, sizeof(buf),
	    &len, fake_resolve, &ctx, err, sizeof(err)) == 0);
	memset(&d, 0, sizeof(d));
	CHECK(zaarch64_decode_one(0x1000, buf, sizeof(buf), &d) == 0);
	CHECK(d.kind == ZINSN_JMP);
	CHECK(d.has_target);
	CHECK(d.target == 0x1008);

	err[0] = 0;
	CHECK(zaarch64_assemble_one(0x1000, "bl pc+8", buf, sizeof(buf),
	    &len, fake_resolve, &ctx, err, sizeof(err)) == 0);
	memset(&d, 0, sizeof(d));
	CHECK(zaarch64_decode_one(0x1000, buf, sizeof(buf), &d) == 0);
	CHECK(d.kind == ZINSN_CALL);

	err[0] = 0;
	CHECK(zaarch64_assemble_one(0x1000, "ret", buf, sizeof(buf),
	    &len, fake_resolve, &ctx, err, sizeof(err)) == 0);
	memset(&d, 0, sizeof(d));
	CHECK(zaarch64_decode_one(0x1000, buf, sizeof(buf), &d) == 0);
	CHECK(d.kind == ZINSN_RET);

	return 0;
}

int
main(void)
{
	int rc = 0;
	rc |= test_basic_words();
	rc |= test_branches();
	rc |= test_arith();
	rc |= test_negative();
	rc |= test_patch();
	rc |= test_resolver();
	rc |= test_roundtrip();
	if (rc == 0)
		printf("test_aarch64_asm: OK\n");
	return rc;
}
