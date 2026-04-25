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
#include "zdbg_bp.h"
#include "zdbg_cmd.h"

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

int
zdbg_set_arch(struct zdbg *d, enum zarch arch)
{
	const struct zarch_ops *ops;

	if (d == NULL)
		return -1;
	ops = zarch_get(arch);
	if (ops == NULL)
		return -1;
	d->arch_id = arch;
	d->arch = ops;
	/* Reinitialize the breakpoint table so it picks up the new
	 * arch-owned breakpoint bytes/length. */
	zbp_table_init(&d->bps, d->arch);
	return 0;
}

int
zdbg_select_arch_for_target(struct zdbg *d)
{
	/*
	 * Both currently supported OS backends (Linux ptrace and
	 * the Windows Debug API) only run x86-64 targets.  Future
	 * ELF e_machine / PE Machine detection plugs in here.
	 */
	return zdbg_set_arch(d, ZARCH_X86_64);
}
