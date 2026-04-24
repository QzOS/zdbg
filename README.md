# zdbg

A small DEBUG.COM-inspired debugger for modern x86-64 Linux and
Windows.

## Current status

* Linux ptrace backend: minimal launch/attach/read/write/register/
  continue/singlestep support against a single traced x86-64 task.
* Windows backend: still stubbed.
* Breakpoints: software breakpoints (`int3`) support RIP-1
  correction, original-byte restore, single-step rearm, and
  continue from breakpoint for the current single traced Linux
  task.  Breakpoint rearm is not thread-safe yet; zdbg still
  traces only one task and does not coordinate multiple threads.
* Tiny disassembler: recognizes a small useful x86-64 subset for
  prologues, calls, jumps, stack adjustment, simple moves/tests/
  comparisons.  Unknown instructions are still shown as `db`.
* Linux memory maps: `lm` lists `/proc/<pid>/maps` and address
  expressions support `module+offset` for mapped modules.
  Module-relative expressions are *mapping-relative*, not ELF
  symbol/RVA aware yet.
* Linux ELF symbols: `sym` reads ELF64 `.symtab`/`.dynsym` from
  mapped module files and resolves simple symbol expressions
  such as `main`, `foo`, `libc:malloc`.  This is not DWARF or
  source-level debugging.
* Proceed/step-over (`p`) only supports direct `call rel32`
  initially.  Indirect calls and complex instruction decoding
  remain out of scope.
* Thread handling: single traced task only; no clone/fork
  following, no `PTRACE_O_TRACECLONE`, no `/proc/<pid>/task`
  enumeration on attach.
* No DWARF/PDB, no source-line debugging, no hardware
  breakpoints or watchpoints, no remote debugging.

On non-Linux hosts every target-dependent command still prints

    target operation not available in this backend yet

until a real backend is implemented for that platform.

## Non-goals

zdbg is not trying to become GDB or LLDB.  The first framework
deliberately avoids:

* DWARF / PDB / source-line debugging
* a full x86 assembler or disassembler
* Capstone / Keystone / libbfd / LLVM
* scripting, plugins, remote debugging, GUI
* file patching, hardware breakpoints

## Build

    cmake -S . -B build
    cmake --build build
    ctest --test-dir build

No external dependencies.  Builds with GCC, Clang, or (later)
MSVC.

Run the debugger:

    ./build/zdbg
    ./build/zdbg ./build/examples/testprog

## Command sketch

    ?                    help
    q                    quit
    l [path [args...]]   launch target
    la pid               attach to pid
    ld                   detach from target
    k                    kill target
    r [reg [value]]      show/set registers
    d [addr [len]]       dump memory
    x [addr [len]]       alias for d
    e addr bytes...      write bytes
    f addr len bytes...  fill memory
    u [addr [count]]     tiny unassemble
    a [addr]             tiny assemble
    pa addr len insn     patch instruction + NOP fill
    ij addr              invert jz/jnz
    b [addr]             list/set breakpoint
    bc n|*               clear breakpoint
    bd n                 disable breakpoint
    be n                 enable breakpoint
    lm [addr]            list maps or show map containing address
    sym [filter|-r]      list/search loaded ELF symbols, or refresh
    g                    continue (waits for next stop)
    t                    single step (waits for next stop)
    p [count]            proceed / step over direct call

Address expressions accept raw numbers (default hex), registers
(`rip+10`), and — on Linux, after a target has been
launched/attached — mapping-relative module names and ELF
symbol names:

    main+1000                        main executable mapping + 0x1000
    libc+18a70                       selected libc mapping + 0x18a70
    /lib/.../libc.so.6+20            full-path mapping + 0x20
    [stack]-20                       bracketed special map - 0x20
    map:1+30                         Nth mapping + 0x30
    main                             ELF symbol `main` if present,
                                     otherwise the main mapping base
    foo                              ELF symbol `foo` (e.g. static
                                     function, if `.symtab` was kept)
    foo+4                            symbol `foo` + 4
    libc:malloc                      `malloc` from libc module
    libc.so.6:malloc+20              qualified + offset

Resolution precedence for ambiguous cases:

1. Plain numbers and registers (same as before).
2. `name+N` / `name-N` where the LHS matches a mapping
   resolves **mapping-relative** first.  This preserves the
   PR #8 behaviour of `main+1000` and `libc+18a70`.
3. `module:symbol` uses qualified symbol lookup.
4. A bare `name` without `+N`/`-N` tries the exact symbol
   first, then falls back to the mapping base.

Module resolution remains mapping-relative (not ELF image-base
relative).  If a short basename matches more than one mapped
module, the expression fails with an ambiguity message.  If a
symbol is ambiguous (same name in two modules) the expression
prints `ambiguous symbol: <name>`; qualify with `module:name`
to pick one.

Symbols are refreshed automatically on `l`/`la` and after each
`lm`.  Use `sym -r` to force a refresh (useful after the
dynamic loader has mapped new shared libraries).

Known limitations: instruction operands inside `a` / `pa` /
interactive tiny assembly still accept only numbers and
registers; symbol names are not resolved inside assembled
instruction operands in this release.

Typical session:

    l
    lm
    sym main
    b main
    g
    u main 12
    sym -r
    sym libc:malloc

## Architecture overview

    include/        public headers
    src/            core implementation
        target.c        OS-agnostic dispatcher
        target_null.c   fallback backend (non-Linux, errors cleanly)
        os_linux/       Linux ptrace backend (real)
        os_windows/     Win32 Debug API backend (stubbed)
    tests/          CTest-driven unit tests
    examples/       manual target programs (e.g. `testprog`)

Platform-specific headers are confined to the matching backend
file; `<sys/ptrace.h>` only appears under `src/os_linux/` and
`<windows.h>` only appears under `src/os_windows/`.

