/*
 * zdbg_tinydis.h - tiny disassembler.
 *
 * Recognises a small but practical x86-64 subset covering the
 * kinds of instructions common in compiler output: prologues,
 * epilogues, direct calls, direct jumps and jcc, stack pointer
 * adjustment, simple register moves, RIP-relative lea, immediate
 * moves, and common xor/test/cmp.  Unknown or unsupported bytes
 * are emitted as "db 0xNN", which is intentionally DEBUG.COM-like.
 *
 * The decoder also exposes a small amount of structured metadata
 * so that command code (for example `p` / step-over) can reason
 * about branches, calls and fallthrough without re-parsing text.
 */

#ifndef ZDBG_TINYDIS_H
#define ZDBG_TINYDIS_H

#include "zdbg.h"

enum zinsn_kind {
	ZINSN_OTHER = 0,
	ZINSN_NOP,
	ZINSN_INT3,
	ZINSN_RET,
	ZINSN_CALL,
	ZINSN_JMP,
	ZINSN_JCC,
	ZINSN_PUSH,
	ZINSN_POP,
	ZINSN_MOV,
	ZINSN_LEA,
	ZINSN_ADD,
	ZINSN_SUB,
	ZINSN_CMP,
	ZINSN_TEST,
	ZINSN_XOR
};

struct ztinydis {
	zaddr_t addr;
	uint8_t bytes[16];
	size_t len;
	char text[64];

	enum zinsn_kind kind;
	zaddr_t target;
	int has_target;
	int is_call;
	int is_branch;
	int is_cond;
};

int  ztinydis_one(zaddr_t addr, const uint8_t *buf, size_t buflen,
    struct ztinydis *out);
void ztinydis_print(const struct ztinydis *d);

/*
 * Return the address of the instruction following d (d->addr +
 * d->len).  Returns 0 if d is NULL or d->len is 0 (bad decode).
 */
zaddr_t ztinydis_fallthrough(const struct ztinydis *d);

#endif /* ZDBG_TINYDIS_H */
