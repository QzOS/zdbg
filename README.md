# zdbg

A small DEBUG.COM-inspired debugger for modern x86-64 Linux and
Windows.

## Current status

* Linux ptrace backend: minimal launch/attach/read/write/register/
  continue/singlestep support against a single traced x86-64 task.
* Windows backend: first x64 Debug API backend.  Supports
  launch (`CreateProcess` with `DEBUG_ONLY_THIS_PROCESS`),
  attach (`DebugActiveProcess`), detach, kill, memory
  read/write (`ReadProcessMemory`/`WriteProcessMemory`),
  instruction-cache flush, x64 register get/set via
  `CONTEXT`, continue and single-step (trap flag), basic
  debug-event thread tracking, and software breakpoints via
  `EXCEPTION_BREAKPOINT` mapping.  Windows modules/symbols:
  `lm` lists loaded PE modules from debug events and
  `sym`/`b module:symbol` resolve PE export symbols loaded
  from target memory.  `sym kernel32:CreateFileW` and
  `b kernel32:CreateFileW` work for exported symbols.
  PDB/CodeView/private symbols, WOW64, and Windows exception
  policy are not implemented yet.
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
* Symbolization: zdbg formats addresses as nearest ELF symbols
  and annotates stop output plus branch/call targets in `u`
  output.  `addr expr` prints address + nearest symbol + mapping.
* Backtrace: `bt [count]` walks the x86-64 RBP frame chain only;
  there is no DWARF/`.eh_frame` unwinding.  Frames without
  preserved frame pointers (e.g. much of libc compiled with
  `-fomit-frame-pointer`) terminate the trace.
* Hardware breakpoints/watchpoints: Linux x86-64 DR0-DR7
  support for execute, write, and read/write watchpoints.
  Four slots only.  zdbg programs the hardware debug
  registers into **every known traced thread** before each
  resume, so watchpoints fire on any thread that writes the
  watched address.  Very newly-cloned threads may run briefly
  without DR state until the next ptrace stop is observed.
  Windows x64 DR0-DR7 support uses `CONTEXT_DEBUG_REGISTERS`
  for execute, write, and read/write watchpoints through the
  same generic `hb`/`hw`/`hl`/`hc`/`hd`/`he` commands.  Four
  slots only.  Settings are programmed into every known
  debug-event thread; very new threads may run briefly
  without DR state until the next debug event is processed.
  Hardware traps on Windows arrive as `EXCEPTION_SINGLE_STEP`
  and are distinguished from user single-step via DR6.
  No thread-specific hwbp UI, no WOW64/32-bit target DR
  support.
* Proceed/step-over (`p`) only supports direct `call rel32`
  initially.  Indirect calls and complex instruction decoding
  remain out of scope.
* Thread awareness: Linux backend tracks multiple traced
  threads, supports `th` list/select, sets
  `PTRACE_O_TRACECLONE` on launch, attaches to every TID under
  `/proc/<pid>/task` on attach, uses `waitpid(-1, __WALL)` to
  observe events from any traced thread, and follows
  `PTRACE_EVENT_CLONE` so newly-born worker threads are added
  to the table automatically.  `g` continues all stopped
  non-exited threads; `t` single-steps the selected thread
  only and tries to keep other threads paused (best-effort
  all-stop).  Stop output includes the stopping TID once more
  than one thread is known.  This is still all-stop and
  first-pass; software breakpoint rearm is best-effort and
  not fully race-free in heavy multi-threaded targets, no
  thread-specific breakpoints, no non-stop mode, no
  fork/exec following.
* Signal handling: Linux stops expose pending signals per
  thread; `sig` can clear or set the signal delivered on next
  resume; `handle` controls stop/pass/print policy.  Signal
  policy is process-wide inside zdbg, not per-thread.  Windows
  exception handling: zdbg names common Windows exception
  codes, exposes the pending exception with `ex`, and uses
  `handle` stop/pass/print policy for Windows exceptions.
  `pass` means `DBG_EXCEPTION_NOT_HANDLED`; `nopass` means
  `DBG_CONTINUE`.  Breakpoint, hardware-breakpoint, and
  single-step events are not routed through the exception
  policy and remain debugger-internal.  No SEH chain decoding,
  no C++ exception object decoding, no CLR exception decoding,
  and no Windows source/PDB integration.
* Patch journal: user memory writes (`e`, `f`, `a`, `pa`, `ij`)
  are recorded with old/new bytes and can be listed (`pl`),
  reverted (`pu`), reapplied (`pr`), saved as raw bytes or a
  simple textual script (`ps`), and, for file-backed mappings,
  explicitly written back to disk (`pw`) only when the current
  file bytes still match the recorded old bytes.  Software
  breakpoint memory writes are not recorded.  The journal is
  cleared on new launch/attach and kept across detach/kill so
  patches can still be inspected or saved after the process is
  gone.
* No DWARF/PDB, no source-line debugging, no remote debugging.
* Windows support is younger than Linux support.  No PDB, no
  CodeView, no private/COFF symbols, no WOW64.  Windows
  exception control is now available: named exception codes,
  `ex` for pending-event inspection/pass/nopass/clear, and
  `handle` stop/pass/print policy for Windows exceptions.
  Windows hardware watchpoints rely on
  known debug-event threads and are not yet a fully non-stop
  multi-thread solution.  Windows `lm` lists module images,
  not full `VirtualQueryEx` memory regions.  Windows symbols
  are PE exports only (no imports, no forwarders).  Windows
  patch persistence: zdbg can persist in-place patches to PE
  files when the patched RVA maps entirely to raw bytes in one
  PE section and the current file bytes still match recorded
  old bytes.  It does not update PE checksum, certificates,
  signatures, relocations, or metadata, so any Authenticode
  signature on the file will become invalid after `pw`.
  POSIX `sig`/`handle` for signals remains Linux-only; on
  Windows `handle` operates on exception codes instead and
  `ex` manages the pending `ContinueDebugEvent` status.  `bt`
  on Windows relies on frame pointers as on Linux.

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
* general binary rewriting (ELF metadata, relocations,
  section growth, checksums, signatures, PE/COFF or Mach-O
  writing, trampoline generation, or diff formats).  `pw` does
  only raw byte patches to file-backed mappings and only when
  the current file bytes match the recorded old bytes.

## Build

    cmake -S . -B build
    cmake --build build
    ctest --test-dir build

No external dependencies.  Builds with GCC, Clang, or MSVC.
The same commands work on Windows inside a Developer PowerShell:

    cmake -S . -B build
    cmake --build build
    ctest --test-dir build

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
    pl                   list recorded user patches
    pu id|*              undo/revert patch(es) in live memory
    pr id|*              reapply reverted patch(es)
    pf id                show file mapping for patch
    ps id path           save raw patch bytes for one patch
    ps * path            save textual patch script for all patches
    pw id|*              write applied patch(es) back to mapped
                         file, conservatively (old bytes must match)
    b [addr]             list/set breakpoint
    bc n|*               clear breakpoint
    bd n                 disable breakpoint
    be n                 enable breakpoint
    hb addr              set hardware execute breakpoint
    hw addr len w|rw     set hardware data watchpoint
    hl                   list hardware breakpoints/watchpoints
    hc n|*               clear hardware breakpoint/watchpoint
    hd n                 disable hardware slot
    he n                 enable hardware slot
    lm [addr]            list maps or show map containing address
    sym [filter|-r]      list/search loaded ELF symbols, or refresh
    addr expr            show address, nearest symbol, containing map
    bt [count]           frame-pointer backtrace (default 16 frames)
    g                    continue (waits for next stop)
    t                    single step (waits for next stop)
    p [count]            proceed / step over direct call
    th [tid|index]       list/select traced thread
    sig                  show pending signal for selected thread
    sig -l               list known signals
    sig 0                clear pending signal
    sig SIGSEGV          set pending signal for next resume
    ex                   show pending Windows exception
    ex -l                list known Windows exception names
    ex 0                 suppress pending exception (DBG_CONTINUE)
    ex pass|nopass       set pending exception continuation
    ex CODE pass|nopass  set pending exception continuation (guarded)
    handle [name [opts]] show/set signal stop/pass/print policy on
                         Linux, or Windows exception policy on Windows

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

`bt` is frame-pointer based only; optimized code compiled with
omitted frame pointers may produce short or incorrect traces.
The example target (`examples/testprog`) is built with
`-fno-omit-frame-pointer` on GCC/Clang so manual sessions can
see multi-frame traces.

Hardware breakpoints/watchpoints are per-thread on x86: zdbg
programs DR0..DR7 into every currently-known traced thread
before each resume so watchpoints trigger regardless of which
thread writes the watched address.  Newly-cloned threads may
execute briefly without DR state until the backend observes
the next ptrace stop and reprograms them.  x86 has no
read-only data watchpoint encoding, so `hw` accepts only
`w` (write) and `rw` (read/write).  Data watchpoint lengths
must be 1, 2, 4 or 8 bytes and the address must be naturally
aligned (`addr % len == 0`).  Hardware execute breakpoints
stop at the watched instruction without patching code with
`0xcc`.

Software breakpoint rearm in multi-threaded programs is
best-effort and not fully race-free yet: between the trap and
the internal single-step + reinstall, another thread can run
briefly over the uninstalled byte.  Fixing this properly
requires a stronger all-stop guarantee than the current
backend provides.

Patch persistence (`pw`) writes raw file bytes only.  It does
not update ELF/PE metadata, relocations, checksums, signatures,
or section sizes, and will not create files, follow deleted
mappings, or touch bracketed/anonymous mappings.  On Windows it
also refuses synthetic/device-path module names, patches whose
RVA lands in BSS/uninitialized PE virtual tail bytes, and
ranges that span more than one PE section.  It refuses to write
when the current on-disk bytes at the mapped file offset no
longer match the bytes that were captured when the patch was
recorded.  Undo is byte-level and not
dependency-aware for overlapping patches: `pu id` restores the
original old bytes regardless of any later overlapping patch.
Reapply (`pr`) is symmetric to `pu`.  The journal has a fixed
capacity of 256 patches of up to 256 bytes each; writes
exceeding that are rejected with a clear message.  Script
loading is not implemented yet.

Typical session:

    l
    lm
    sym main
    b main
    g
    addr rip
    u main 12
    bt
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
    examples/       manual target programs
                     - testprog     single-threaded
                     - testthreads  pthread-based, for `th` sessions
                     - testsignals  raises SIGUSR1/SIGUSR2 for
                                    `sig`/`handle` sessions

Platform-specific headers are confined to the matching backend
file; `<sys/ptrace.h>` only appears under `src/os_linux/` and
`<windows.h>` only appears under `src/os_windows/`.

