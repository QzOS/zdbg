/*
 * zdbg_regfile.h - generic integer register-file view.
 *
 * Phase-1 architecture-neutral register abstraction.  The OS
 * backends still fetch and store registers through `struct
 * zregs` (which is x86-64-shaped today); this header introduces
 * an architecture-neutral view that command-level code and the
 * expression evaluator can use without naming x86 registers
 * directly.
 *
 * Each register has a fixed descriptor (name, width in bits,
 * role, writable flag) and a current integer value with a
 * `valid` flag.  Vector/FPU registers are out of scope for
 * this phase; everything here is a 64-bit integer.
 *
 * Aliases such as `pc`, `sp`, and `fp` resolve to the same
 * underlying canonical register through a per-architecture
 * alias table.  No alias holds its own storage.
 */

#ifndef ZDBG_REGFILE_H
#define ZDBG_REGFILE_H

#include "zdbg.h"
#include "zdbg_arch.h"

struct zregs;

/*
 * Maximum number of canonical register descriptors per
 * architecture.  Sized generously so future architectures with
 * larger GPR sets fit without resizing the consumers.  x86-64
 * uses 18 entries today.
 */
#define ZDBG_MAX_REGS        128
#define ZDBG_REG_NAME_MAX    16

enum zreg_role {
	ZREG_ROLE_NONE = 0,
	ZREG_ROLE_PC,
	ZREG_ROLE_SP,
	ZREG_ROLE_FP
};

struct zreg_desc {
	char     name[ZDBG_REG_NAME_MAX];
	uint16_t bits;
	uint8_t  role;		/* enum zreg_role packed for size */
	uint8_t  writable;
};

struct zreg_alias {
	char name[ZDBG_REG_NAME_MAX];
	char canonical[ZDBG_REG_NAME_MAX];
};

struct zreg_value {
	uint64_t value;
	int      valid;
};

/*
 * The descriptor table and alias table are per-architecture
 * static data, referenced (not owned) by the register file.
 */
struct zreg_file {
	enum zarch arch;
	const struct zreg_desc *desc;
	const struct zreg_alias *aliases;
	int desc_count;
	int alias_count;
	int count;	/* equals desc_count for convenience */
	struct zreg_value val[ZDBG_MAX_REGS];
};

/*
 * Initialize `rf` for `arch`.  After init the register file has
 * the architecture's descriptor and alias tables wired in but
 * every value is marked invalid.  For architectures with no
 * register file (ZARCH_NONE, ZARCH_AARCH64 today) the file is
 * left empty: `count` is 0 and every lookup fails cleanly.
 */
void zregfile_init(struct zreg_file *rf, enum zarch arch);

/*
 * Convert a backend `struct zregs` snapshot into the generic
 * register file view.  Returns 0 on success and -1 if the
 * architecture has no defined mapping (e.g. ZARCH_AARCH64).
 * On success every descriptor's `valid` flag is set to 1.
 */
int  zregfile_from_zregs(struct zreg_file *rf, enum zarch arch,
    const struct zregs *zr);

/*
 * Inverse of zregfile_from_zregs(): copy current register
 * values back into a `struct zregs`.  Returns 0 on success and
 * -1 if the architecture has no defined mapping.
 */
int  zregfile_to_zregs(const struct zreg_file *rf, struct zregs *zr);

/*
 * Lookup register `name` (case-insensitive), resolving aliases
 * to their canonical entry.  On success writes the value to
 * `*vp` and returns 0.  Returns -1 if the name is unknown or
 * the value is invalid.
 */
int  zregfile_get(const struct zreg_file *rf, const char *name,
    uint64_t *vp);

/*
 * Set register `name` to `v`.  Honors aliases.  Returns -1 if
 * the name is unknown or the descriptor is not writable.
 */
int  zregfile_set(struct zreg_file *rf, const char *name, uint64_t v);

/*
 * Resolve a role to its current value.  Returns -1 if the
 * architecture does not assign that role or the role's value
 * is not valid.
 */
int  zregfile_get_role(const struct zreg_file *rf, enum zreg_role role,
    uint64_t *vp);
int  zregfile_set_role(struct zreg_file *rf, enum zreg_role role,
    uint64_t v);

/*
 * Canonical name for `role` on this register file, or NULL if
 * the architecture does not assign that role.
 */
const char *zregfile_role_name(const struct zreg_file *rf,
    enum zreg_role role);

/*
 * Print the register file in the architecture's preferred
 * layout.  For ZARCH_X86_64 this matches the legacy zregs_print
 * output; for architectures without descriptors a one-line
 * "registers unsupported" message is printed.
 */
void zregfile_print(const struct zreg_file *rf);

#endif /* ZDBG_REGFILE_H */
