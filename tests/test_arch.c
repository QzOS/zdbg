/*
 * test_arch.c - basic tests for the architecture ops abstraction.
 *
 * Verifies that:
 *   - zarch_get returns sane ops tables for ZARCH_X86_64 and
 *     ZARCH_AARCH64, and NULL for ZARCH_NONE
 *   - x86-64 ops report 0xcc / length 1 / pc - 1 trap correction
 *   - x86-64 decode_one wrapper decodes a known direct call and
 *     reports call/branch/has_target metadata
 *   - x86-64 assemble_patch wrapper still produces the jmpabs
 *     pseudo-instruction (movabs r11, imm64; jmp r11)
 *   - x86-64 PC/SP/FP register accessors map to rip/rsp/rbp
 *   - AArch64 ops report BRK #0 / length 4 and identity trap PC
 *   - AArch64 decode_one and assemble_patch report unsupported
 *     cleanly without crashing
 */

#include <stdio.h>
#include <string.h>

#include "zdbg.h"
#include "zdbg_arch.h"
#include "zdbg_regs.h"

#define CHECK(cond) \
	do { if (!(cond)) { printf("FAIL: %s:%d %s\n", __FILE__, \
	    __LINE__, #cond); return 1; } } while (0)

static int
resolve_number(void *arg, const char *expr, zaddr_t *out)
{
	unsigned long long v;
	(void)arg;
	if (expr == NULL || out == NULL)
		return -1;
	if (sscanf(expr, "%llx", &v) != 1 &&
	    sscanf(expr, "%llu", &v) != 1)
		return -1;
	*out = (zaddr_t)v;
	return 0;
}

static int
test_registry(void)
{
	const struct zarch_ops *x = zarch_get(ZARCH_X86_64);
	const struct zarch_ops *a = zarch_get(ZARCH_AARCH64);
	const struct zarch_ops *n = zarch_get(ZARCH_NONE);

	CHECK(x != NULL);
	CHECK(a != NULL);
	CHECK(n == NULL);
	CHECK(x->arch == ZARCH_X86_64);
	CHECK(a->arch == ZARCH_AARCH64);
	CHECK(x->name != NULL && strstr(x->name, "x86") != NULL);
	CHECK(a->name != NULL && strcmp(a->name, "aarch64") == 0);
	CHECK(zarch_x86_64() == x);
	CHECK(zarch_aarch64() == a);
	return 0;
}

static int
test_x86_breakpoint(void)
{
	const struct zarch_ops *x = zarch_get(ZARCH_X86_64);

	CHECK(x->breakpoint_bytes != NULL);
	CHECK(x->breakpoint_len == 1);
	CHECK(x->breakpoint_bytes[0] == 0xcc);
	CHECK(x->breakpoint_pc_after_trap != NULL);
	CHECK(x->breakpoint_pc_after_trap(0x1001) == 0x1000);
	CHECK(x->breakpoint_pc_after_trap(0) == 0);
	return 0;
}

static int
test_x86_decode_call(void)
{
	const struct zarch_ops *x = zarch_get(ZARCH_X86_64);
	/* call rel32: e8 disp32; here disp32 = +5, so target = next_pc + 5 */
	uint8_t code[5] = { 0xe8, 0x05, 0x00, 0x00, 0x00 };
	struct zdecode d;

	CHECK(x->decode_one != NULL);
	CHECK(x->fallthrough != NULL);
	memset(&d, 0, sizeof(d));
	CHECK(x->decode_one(0x400000, code, sizeof(code), &d) == 0);
	CHECK(d.len == 5);
	CHECK(d.kind == ZINSN_CALL);
	CHECK(d.is_call == 1);
	CHECK(d.has_target == 1);
	CHECK(d.target == 0x400000 + 5 + 5);
	CHECK(x->fallthrough(&d) == 0x400005);
	return 0;
}

static int
test_x86_assemble_patch_jmpabs(void)
{
	const struct zarch_ops *x = zarch_get(ZARCH_X86_64);
	uint8_t buf[16];
	size_t out_len = 0;
	char err[64];

	CHECK(x->assemble_patch != NULL);
	memset(buf, 0, sizeof(buf));
	err[0] = 0;
	/* jmpabs imm64 -> 13 bytes (movabs r11, imm; jmp r11), padded
	 * to patch_len with arch NOP. */
	CHECK(x->assemble_patch(0x400000, 16, "jmpabs 0xdeadbeefcafebabe",
	    buf, sizeof(buf), &out_len, resolve_number, NULL,
	    err, sizeof(err)) == 0);
	CHECK(out_len == 16);
	/* 49 bb = REX.WB + mov r11, imm64 prefix */
	CHECK(buf[0] == 0x49);
	CHECK(buf[1] == 0xbb);
	/* immediate is little-endian deadbeefcafebabe */
	CHECK(buf[2] == 0xbe);
	CHECK(buf[9] == 0xde);
	/* jmp r11 = 41 ff e3 */
	CHECK(buf[10] == 0x41);
	CHECK(buf[11] == 0xff);
	CHECK(buf[12] == 0xe3);
	/* tail padded with x86 NOP 0x90 */
	CHECK(buf[13] == 0x90);
	CHECK(buf[15] == 0x90);
	return 0;
}

static int
test_x86_regs(void)
{
	const struct zarch_ops *x = zarch_get(ZARCH_X86_64);
	struct zregs r;
	zaddr_t v = 0;

	CHECK(x->get_pc != NULL);
	CHECK(x->set_pc != NULL);
	CHECK(x->get_sp != NULL);
	CHECK(x->get_fp != NULL);
	memset(&r, 0, sizeof(r));
	r.rip = 0x401000;
	r.rsp = 0x7fff0000;
	r.rbp = 0x7fff0010;
	CHECK(x->get_pc(&r, &v) == 0 && v == 0x401000);
	CHECK(x->get_sp(&r, &v) == 0 && v == 0x7fff0000);
	CHECK(x->get_fp(&r, &v) == 0 && v == 0x7fff0010);
	CHECK(x->set_pc(&r, 0x402000) == 0);
	CHECK(r.rip == 0x402000);
	CHECK(x->pc_reg_name != NULL && strcmp(x->pc_reg_name, "rip") == 0);
	CHECK(x->sp_reg_name != NULL && strcmp(x->sp_reg_name, "rsp") == 0);
	CHECK(x->fp_reg_name != NULL && strcmp(x->fp_reg_name, "rbp") == 0);
	return 0;
}

static int
test_x86_assemble_one(void)
{
	const struct zarch_ops *x = zarch_get(ZARCH_X86_64);
	uint8_t buf[ZDBG_MAX_INSN_BYTES];
	size_t out_len = 0;
	char err[64];

	CHECK(x->assemble_one != NULL);

	memset(buf, 0xee, sizeof(buf));
	err[0] = 0;
	CHECK(x->assemble_one(0x400000, "nop", buf, sizeof(buf), &out_len,
	    resolve_number, NULL, err, sizeof(err)) == 0);
	CHECK(out_len == 1);
	CHECK(buf[0] == 0x90);
	/* assemble_one must NOT NOP-pad: byte after the encoding is
	 * untouched */
	CHECK(buf[1] == 0xee);

	memset(buf, 0xee, sizeof(buf));
	out_len = 0;
	CHECK(x->assemble_one(0x400000, "int3", buf, sizeof(buf),
	    &out_len, resolve_number, NULL, err, sizeof(err)) == 0);
	CHECK(out_len == 1);
	CHECK(buf[0] == 0xcc);

	memset(buf, 0xee, sizeof(buf));
	out_len = 0;
	CHECK(x->assemble_one(0x400000, "jmpabs 0xdeadbeefcafebabe",
	    buf, sizeof(buf), &out_len, resolve_number, NULL, err,
	    sizeof(err)) == 0);
	CHECK(out_len == 13);
	CHECK(buf[0] == 0x49 && buf[1] == 0xbb);
	CHECK(buf[2] == 0xbe);
	CHECK(buf[9] == 0xde);
	CHECK(buf[10] == 0x41 && buf[11] == 0xff && buf[12] == 0xe3);
	/* no NOP padding past the encoding */
	CHECK(buf[13] == 0xee);
	return 0;
}

static int
test_x86_reg_hooks(void)
{
	const struct zarch_ops *x = zarch_get(ZARCH_X86_64);
	struct zregs r;
	uint64_t v = 0;

	CHECK(x->regs_print != NULL);
	CHECK(x->regs_get_by_name != NULL);
	CHECK(x->regs_set_by_name != NULL);
	memset(&r, 0, sizeof(r));
	r.rip = 0x401000;
	r.rsp = 0x7fff0000;
	r.rbp = 0x7fff0010;
	r.rax = 0x1122334455667788ULL;
	CHECK(x->regs_get_by_name(&r, "rip", &v) == 0 && v == 0x401000);
	CHECK(x->regs_get_by_name(&r, "rsp", &v) == 0 && v == 0x7fff0000);
	CHECK(x->regs_get_by_name(&r, "rbp", &v) == 0 && v == 0x7fff0010);
	CHECK(x->regs_get_by_name(&r, "rax", &v) == 0 &&
	    v == 0x1122334455667788ULL);
	CHECK(x->regs_set_by_name(&r, "rip", 0x402000) == 0);
	CHECK(r.rip == 0x402000);
	CHECK(x->regs_set_by_name(&r, "rax", 0x42) == 0);
	CHECK(r.rax == 0x42);
	CHECK(x->regs_get_by_name(&r, "nosuch", &v) == -1);
	CHECK(x->regs_set_by_name(&r, "nosuch", 0) == -1);
	return 0;
}

static int
test_aarch64_breakpoint(void)
{
	const struct zarch_ops *a = zarch_get(ZARCH_AARCH64);
	/* BRK #0 little-endian: 00 00 20 d4 */
	const uint8_t expected[4] = { 0x00, 0x00, 0x20, 0xd4 };

	CHECK(a->breakpoint_bytes != NULL);
	CHECK(a->breakpoint_len == 4);
	CHECK(memcmp(a->breakpoint_bytes, expected, 4) == 0);
	/* AArch64 PC-after-trap is identity; no x86 -1 reuse. */
	CHECK(a->breakpoint_pc_after_trap != NULL);
	CHECK(a->breakpoint_pc_after_trap(0x1000) == 0x1000);
	CHECK(a->breakpoint_pc_after_trap(0x1004) == 0x1004);
	return 0;
}

static int
test_aarch64_unsupported(void)
{
	const struct zarch_ops *a = zarch_get(ZARCH_AARCH64);
	uint8_t code[4] = { 0x00, 0x00, 0x00, 0x00 };
	uint8_t buf[16];
	struct zdecode d;
	struct zregs r;
	zaddr_t v = 0;
	size_t out_len = 0;
	size_t used = 0;
	char err[64];

	memset(&d, 0, sizeof(d));
	memset(&r, 0, sizeof(r));
	CHECK(a->decode_one != NULL);
	CHECK(a->decode_one(0x1000, code, sizeof(code), &d) == -1);

	err[0] = 0;
	CHECK(a->assemble_patch != NULL);
	CHECK(a->assemble_patch(0x1000, 4, "nop", buf, sizeof(buf),
	    &out_len, resolve_number, NULL, err, sizeof(err)) == -1);
	CHECK(err[0] != 0);

	CHECK(a->invert_jcc != NULL);
	CHECK(a->invert_jcc(buf, sizeof(buf), &used) == -1);

	CHECK(a->get_pc(&r, &v) == -1);
	CHECK(a->set_pc(&r, 0x1000) == -1);
	CHECK(a->get_sp(&r, &v) == -1);
	CHECK(a->get_fp(&r, &v) == -1);

	/* assemble_one: unsupported with diagnostic */
	err[0] = 0;
	out_len = 0;
	CHECK(a->assemble_one != NULL);
	CHECK(a->assemble_one(0x1000, "nop", buf, sizeof(buf), &out_len,
	    resolve_number, NULL, err, sizeof(err)) == -1);
	CHECK(err[0] != 0);
	CHECK(strstr(err, "aarch64") != NULL);

	/* register hooks: present and unsupported */
	CHECK(a->regs_print != NULL);
	CHECK(a->regs_get_by_name != NULL);
	CHECK(a->regs_set_by_name != NULL);
	CHECK(a->regs_get_by_name(&r, "x0", &(uint64_t){0}) == -1);
	CHECK(a->regs_set_by_name(&r, "x0", 0) == -1);

	/* backtrace: unsupported */
	CHECK(a->backtrace_fp != NULL);
	CHECK(a->backtrace_fp(NULL, &r, NULL, 1, NULL, NULL) == -1);
	return 0;
}

/*
 * Verify the host/backend support helper agrees with the active
 * compile-time backend.  Only the native architecture is
 * supported; cross-architecture debugging is rejected.
 */
static int
test_backend_supports_arch(void)
{
	CHECK(zdbg_backend_supports_arch(ZARCH_NONE) == 0);
#if defined(__linux__) && defined(__aarch64__)
	CHECK(zdbg_backend_supports_arch(ZARCH_AARCH64) == 1);
	CHECK(zdbg_backend_supports_arch(ZARCH_X86_64) == 0);
#elif defined(__linux__) && defined(__x86_64__)
	CHECK(zdbg_backend_supports_arch(ZARCH_X86_64) == 1);
	CHECK(zdbg_backend_supports_arch(ZARCH_AARCH64) == 0);
#elif defined(_WIN32)
	CHECK(zdbg_backend_supports_arch(ZARCH_X86_64) == 1);
	CHECK(zdbg_backend_supports_arch(ZARCH_AARCH64) == 0);
#endif
	return 0;
}

int
main(void)
{
	if (test_registry()) return 1;
	if (test_x86_breakpoint()) return 1;
	if (test_x86_decode_call()) return 1;
	if (test_x86_assemble_patch_jmpabs()) return 1;
	if (test_x86_regs()) return 1;
	if (test_x86_assemble_one()) return 1;
	if (test_x86_reg_hooks()) return 1;
	if (test_aarch64_breakpoint()) return 1;
	if (test_aarch64_unsupported()) return 1;
	if (test_backend_supports_arch()) return 1;
	printf("test_arch ok\n");
	return 0;
}
