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
* Linux memory maps: `lm` lists `/proc/<pid>/maps` and address
  expressions support `module+offset` for mapped modules.
  Module-relative expressions are *mapping-relative*, not ELF
  symbol/RVA aware yet.
* Thread handling: single traced task only; no clone/fork
  following, no `PTRACE_O_TRACECLONE`, no `/proc/<pid>/task`
  enumeration on attach.
* No DWARF/PDB, no symbols, no hardware
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
    g                    continue (waits for next stop)
    t                    single step (waits for next stop)

Address expressions accept raw numbers (default hex), registers
(`rip+10`), and — on Linux, after a target has been
launched/attached — mapping-relative module names:

    main+1000                        main executable mapping + 0x1000
    libc+18a70                       selected libc mapping + 0x18a70
    /lib/.../libc.so.6+20            full-path mapping + 0x20
    [stack]-20                       bracketed special map - 0x20
    map:1+30                         Nth mapping + 0x30

Module resolution is mapping-relative (not ELF image-base /
symbol aware).  If a short basename matches more than one mapped
module, the expression fails with an ambiguity message.

Typical session:

    l
    lm
    u main+1000 10
    b main+1180
    pa main+1190 6 jmp main+1200

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

