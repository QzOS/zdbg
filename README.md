# zdbg

A small DEBUG.COM-inspired debugger for modern x86-64 Linux and
Windows.

## Current status

Framework only.  The REPL, expression parser, tiny patch
assembler/disassembler, breakpoint table and OS abstraction are
all in place, but target control (ptrace on Linux, the Win32
Debug API on Windows) is still stubbed out.  Target-dependent
commands print

    target operation not available in this backend yet

until a real backend is implemented in a follow-up issue.

## Non-goals

zdbg is not trying to become GDB or LLDB.  The first framework
deliberately avoids:

* DWARF / PDB / source-line debugging
* a full x86 assembler or disassembler
* Capstone / Keystone / libbfd / LLVM
* scripting, plugins, remote debugging, GUI
* file patching, module enumeration, hardware breakpoints

## Build

    cmake -S . -B build
    cmake --build build
    ctest --test-dir build

No external dependencies.  Builds with GCC, Clang, or (later)
MSVC.

Run the debugger:

    ./build/zdbg
    ./build/zdbg ./examples/testprog

## Command sketch

    ?                    help
    q                    quit
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
    g                    continue
    t                    single step

## Architecture overview

    include/        public headers
    src/            core implementation
        target.c        OS-agnostic dispatcher
        target_null.c   fallback backend
        os_linux/       Linux ptrace backend (stubbed)
        os_windows/     Win32 Debug API backend (stubbed)
    tests/          CTest-driven unit tests
    examples/       manual target programs

Platform-specific headers are confined to the matching backend
file; `<sys/ptrace.h>` only appears under `src/os_linux/` and
`<windows.h>` only appears under `src/os_windows/`.

