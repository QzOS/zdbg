/*
 * zdbg_cmd.h - command dispatch and REPL interface.
 */

#ifndef ZDBG_CMD_H
#define ZDBG_CMD_H

#include "zdbg.h"
#include "zdbg_target.h"
#include "zdbg_bp.h"
#include "zdbg_hwbp.h"
#include "zdbg_regs.h"
#include "zdbg_maps.h"
#include "zdbg_signal.h"
#include "zdbg_exception.h"
#include "zdbg_symbols.h"
#include "zdbg_patch.h"

struct zdbg {
	struct ztarget target;
	struct zbp_table bps;
	struct zhwbp_table hwbps;
	struct zregs regs;
	struct zmap_table maps;
	struct zmap_table regions;
	struct zsym_table syms;
	struct zsig_table sigs;
	struct zexc_table excs;
	struct zpatch_table patches;
	zaddr_t dump_addr;
	zaddr_t asm_addr;
	int have_regs;
	int have_maps;
	int have_regions;
	int have_syms;
	int target_argc;
	char **target_argv;
	int stopped_bp;		/* id of breakpoint currently stopped on, -1 otherwise */
	int stopped_hwbp;	/* id of hw breakpoint currently stopped on, -1 otherwise */
};

void zdbg_init(struct zdbg *d);
void zdbg_fini(struct zdbg *d);
int  zcmd_exec(struct zdbg *d, const char *line);
int  zrepl_run(struct zdbg *d);

#endif /* ZDBG_CMD_H */
