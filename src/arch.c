/*
 * arch.c - architecture ops registry.
 *
 * Single entry point that turns a generic enum zarch identifier
 * into the appropriate ops table.  The debugger core selects an
 * architecture per target (currently always x86-64 because both
 * OS backends are x86-64-only) and stores the resulting pointer
 * in struct zdbg.
 */

#include <stddef.h>

#include "zdbg_arch.h"

const struct zarch_ops *
zarch_get(enum zarch arch)
{
	switch (arch) {
	case ZARCH_X86_64:
		return zarch_x86_64();
	case ZARCH_AARCH64:
		return zarch_aarch64();
	case ZARCH_NONE:
	default:
		return NULL;
	}
}
