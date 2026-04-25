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
#include "zdbg_regfile.h"

/*
 * Native target architecture for the active backend.  Currently
 * the supported backends only run native targets: cross-arch
 * debugging is not implemented.
 */
static enum zarch
zarch_native_for_backend(void)
{
#if defined(__linux__) && defined(__aarch64__)
	return ZARCH_AARCH64;
#elif defined(__linux__) && defined(__x86_64__)
	return ZARCH_X86_64;
#elif defined(_WIN32)
	return ZARCH_X86_64;
#else
	return ZARCH_NONE;
#endif
}

int
zdbg_backend_supports_arch(enum zarch arch)
{
	if (arch == ZARCH_NONE)
		return 0;
	return arch == zarch_native_for_backend() ? 1 : 0;
}

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
	/* Initialize the generic register-file view for this arch.
	 * Values become valid once refresh_regs() runs. */
	zregfile_init(&d->regfile, arch);
	d->have_regfile = 0;
	return 0;
}

int
zdbg_select_arch_for_target(struct zdbg *d)
{
	enum zarch arch;

	if (d == NULL)
		return -1;
	/*
	 * Prefer the architecture the OS backend reported for the
	 * current target.  If no target is loaded yet, fall back
	 * to the backend's native architecture so the early REPL
	 * still has a sensible default.
	 */
	arch = d->target.arch;
	if (arch == ZARCH_NONE)
		arch = zarch_native_for_backend();
	if (arch == ZARCH_NONE)
		return -1;
	return zdbg_set_arch(d, arch);
}
