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
* Memory maps: on Linux, `lm` lists `/proc/<pid>/maps`; on
  Windows, `lm` lists `VirtualQueryEx` committed regions with
  protection/type, and `lm -m` lists the PE module table used
  for `module+offset` expressions and PE export symbols.
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
* Patch journal: user memory writes (`e`, `f`, `a`, `pa`, `ij`,
  `m`, `rf`) are recorded with old/new bytes and can be listed
  (`pl`), reverted (`pu`), reapplied (`pr`), saved as raw bytes
  or a simple textual script (`ps`), and, for file-backed
  mappings, explicitly written back to disk (`pw`) only when the
  current file bytes still match the recorded old bytes.
  Software breakpoint memory writes are not recorded.  The
  journal is cleared on new launch/attach and kept across
  detach/kill so patches can still be inspected or saved after
  the process is gone.  `m` and `rf` are journaled user writes
  that may produce multiple patch records (one per
  `ZDBG_PATCH_MAX_BYTES` chunk) and stop with a clear message
  if the patch journal fills mid-stream.  There is no automatic
  rollback on partial failure; recorded chunks can still be
  reverted with `pu`.  `wf` may leave a partial output file if
  target memory becomes unreadable mid-dump and reports the
  partial byte count in that case.  `c`, `m`, `wf`, and `rf` do
  raw bytes only: no loader, relocation, or file-format
  semantics are applied.
* No DWARF/PDB, no source-line debugging, no remote debugging.
* Windows support is younger than Linux support.  No PDB, no
  CodeView, no private/COFF symbols, no WOW64.  Windows
  exception control is now available: named exception codes,
  `ex` for pending-event inspection/pass/nopass/clear, and
  `handle` stop/pass/print policy for Windows exceptions.
  Windows hardware watchpoints rely on
  known debug-event threads and are not yet a fully non-stop
  multi-thread solution.  Windows `lm` shows full
  `VirtualQueryEx` committed memory regions with protection and
  type information; `lm -m` shows the loaded PE module table
  used for `module+offset` expressions and PE export symbols,
  while `lm -r` shows the region view explicitly.  Windows `lm`
  is not a full VAD/heap/stack analyzer: private regions are
  shown generically (`[private]`/`[private guard]`/`[mapped]`)
  and zdbg does not identify individual heaps or stacks.
  VirtualQueryEx regions are not treated as raw file-backed
  patch targets.  Windows symbols
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

## Command-line usage

    zdbg [options] [target [args...]]

    Options:
      -x, --execute PATH   execute commands from script file
                           (may be repeated; max 16)
      -b, --batch          batch mode: exit after scripts/stdin
      -q, --quiet          suppress banner and prompts
      -v, --verbose        echo script commands before execution
          --no-init        do not load $HOME/.zdbgrc startup file
          --stdin PATH     redirect target stdin from PATH
          --stdout PATH    redirect target stdout to PATH
          --stderr PATH    redirect target stderr to PATH
          --capture-stdout configure file-backed stdout capture
          --capture-stderr configure file-backed stderr capture
          --null-stdin     send EOF on target stdin
          --null-stdout    discard target stdout
          --null-stderr    discard target stderr
      -h, --help           show usage and exit
          --version        show version and exit
          --               end of zdbg options

The target path and its arguments are remembered on the zdbg
state so a bare `l` at the prompt (or in a script) launches it.
Use `--` to keep the target's own dashed arguments distinct from
zdbg options:

    zdbg -x patch.zdbg -- ./prog -not-a-zdbg-option

### Script syntax

Scripts are line-oriented and intentionally simple:

    one command per line
    blank lines are ignored
    full-line comments begin with `;` or `#` after leading whitespace
    quoted paths are supported by commands that use the
        quote-aware splitter (e.g. wf, rf, source)
    no variables, loops, conditionals, macros, or expression
        evaluation beyond the existing address expressions

Lines must be at most 1024 bytes including the newline.  An
over-long line is reported as `path:line: line too long` and
stops execution.  Inline `#`/`;` are **not** treated as comments
because paths and strings may legitimately contain them.

Sourcing scripts interactively (or recursively from another
script) is supported up to a fixed nesting depth (8):

    source path
    . path

Examples:

    zdbg -x examples/scripts/smoke.zdbg ./build/examples/testprog
    zdbg --batch -q -x patch.zdbg ./target
    zdbg --batch ./target < commands.zdbg

### Startup file

If `$HOME/.zdbgrc` exists it is sourced before any `-x` script.
A missing startup file is silently ignored; failures inside it
print a warning but are not fatal.  Pass `--no-init` to skip it.

### Exit status

    0  success (or interactive REPL exit)
    1  a command failed in a script or batch session
    2  usage error, setup error, script-file-open error, or
       script line too long

In interactive mode (no script, no `--batch`) command failures
are reported but do not terminate the REPL.

### Script-friendly assertions

The `check` command family lets scripts verify debugger state
without introducing a scripting language: every check is a
single line that returns command-failure on mismatch.  In batch
or `-x` script mode this stops the script and produces exit
code 1; in interactive mode the failure is reported but the
REPL keeps running.

    check target                    target object exists
    check stopped                   target is stopped
    check running                   target is running
    check exited [code]             target exited (optionally with code)
    check stop reason               last stop reason matches
                                    (initial|breakpoint|singlestep|
                                     signal|exception|exit|hwbp|
                                     watchpoint|error)
    check thread [tid|current]      selected thread matches
    check arch NAME                 target architecture name matches
                                    (e.g. `check arch x86-64`)
    check reg name value            register equals expression
    check rip expr                  alias for `check reg rip expr`
                                    (x86-64; use `check pc` in
                                    portable scripts)
    check pc expr                   architecture-neutral PC check
                                    (resolves to `rip` on x86-64)
    check mem addr pattern          memory bytes/string/value match
                                    (raw bytes, -str, -wstr, -u32,
                                     -u64, -ptr same as `s`)
    check symbol name               symbol resolves (rejects raw numbers)
    check nosymbol name             symbol does not resolve
    check map expr                  address belongs to a known map/region
    check expr CONDITION            assert condition expression is true
                                    (same syntax as `cond`, supports
                                     u8/u16/u32/u64/ptr derefs)
    check patch id applied|reverted patch state matches
    check bp id enabled|disabled|installed|removed
    check bp id hits N|ignore N|cond none|EXPR
    check bp id actions N|silent yes|no
    check hwbp id enabled|disabled
    check hwbp id hits N|ignore N|cond none|EXPR
    check hwbp id actions N|silent yes|no
    check file path exists          host file exists (quoted paths ok)
    check file path size n          host file is exactly n bytes long
    assert ...                      alias for check

Successful checks print nothing.  Failed checks print a single
line beginning with `check failed:` (or `assert failed:` /
`expect failed:` for the aliases).  Example:

    l
    check stopped
    check symbol main
    b main
    g
    check stop breakpoint
    check rip main
    q

A simple smoke and patch script live under
`examples/scripts/assert-smoke.zdbg` and
`examples/scripts/assert-patch.zdbg`.

### Target stdio redirection

Launched targets inherit zdbg's stdin/stdout/stderr by default.
The `io` command and the matching CLI options configure how the
**next** launch wires up those three handles:

    io stdin  inherit|null|PATH
    io stdout inherit|null|capture|PATH
    io stderr inherit|null|capture|stdout|PATH
    io reset
    io                       show current configuration
    io show stdout|stderr [n] print up to n bytes of file/capture
    io path stdout|stderr     print configured output path

`null` maps to `/dev/null` on POSIX and `NUL` on Windows.
`capture` allocates a unique file path under `$TMPDIR` (or
`/tmp`) on POSIX and `GetTempPathA()` on Windows; the path is
printed when configured and stays accessible via `io path` and
`io show`.  Capture files are not deleted automatically — they
are useful artifacts for scripts.  Stderr `stdout` aliases stderr
to whatever stdout becomes for the launched process.

Equivalent CLI options apply to the first launch performed by a
script or interactive session:

    --stdin PATH --stdout PATH --stderr PATH
    --capture-stdout --capture-stderr
    --null-stdin --null-stdout --null-stderr

Limitations.  The configuration applies to launched targets
only; `la` (attach) cannot redirect an already-running process's
stdio.  Capture is file-backed, not live pipe streaming, so
output buffered inside the target may not appear until the
target flushes or exits.  No PTY/ConPTY, expect-style matching,
async output events, or stdin injection into a running process
is implemented.

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
    s addr len bytes...  search explicit range for byte pattern
    s -a|-r pattern      search all readable non-guard regions
    s -m module pattern  search one module range
    s -x|-w|-i pattern   restrict region search by perms or mem-type
    s -str "text"        ASCII string pattern (\n \r \t \\ \" \xNN)
    s -wstr "text"       UTF-16LE string pattern
    s -u32 value         little-endian 32-bit value
    s -u64 value         little-endian 64-bit value
    s -ptr expr          pointer-sized value of expression
    s -limit N           cap matches (default 64)
    c addr1 len addr2    compare two memory ranges
    c -limit N ...       cap differences (default 128)
    m src len dst        copy/move memory inside target, journaled
    wf addr len path     write target memory range to host file
    rf path addr [len]   read host file bytes into target memory,
                         journaled
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
    cond b|h id expr     set breakpoint/watchpoint condition
    cond b|h id clear    clear condition
    ignore b|h id count  ignore next count hits
    hits b|h id [reset]  show/reset hit count
    hits b|h * reset     reset every breakpoint of that kind
    actions b|h id                  show action list
    actions b|h id add LINE...      append action line
    actions b|h id del N            delete action line
    actions b|h id clear            clear actions and silent flag
    actions b|h id silent on|off    suppress normal stop line
    commands b|h id ...             alias for actions
    trace b ADDR [TEXT...]          create silent software tracepoint
    trace h ID   [TEXT...]          turn existing hwbp into tracepoint
    printf TEXT...                  print literal text (\n \t \r \\ \"
                                    \xNN escapes; no format substitution)
    print [/x|/d|/a] EXPR           evaluate EXPR and print its value;
    eval  [/x|/d|/a] EXPR             supports u8/u16/u32/u64/ptr deref
                                      (`/x` hex only, `/d` decimal only,
                                      `/a` add map/region annotation)
    lm [-m|-r] [addr]    list maps/regions or show containing entry
    sym [filter|-r]      list/search loaded ELF symbols, or refresh
    addr expr            show address, nearest symbol, containing map
    bt [count]           frame-pointer backtrace (default 16 frames)
    arch                 show selected target architecture
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
    io                   show target stdio config
    io reset             restore inherited stdio
    io stdin inherit|null|PATH
                         configure stdin for next launch
    io stdout inherit|null|capture|PATH
                         configure stdout for next launch
    io stderr inherit|null|capture|stdout|PATH
                         configure stderr for next launch
    io show stdout|stderr [n]
                         print captured/file output up to n bytes
                         (default 4096)
    io path stdout|stderr
                         print configured output path; fails if none
    source path          execute commands from script file
    . path                alias for source
    check ...            script-friendly assertion (see below)
    assert ...           alias for check

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

Value expressions (used by `print`/`eval`, `check expr`, and
breakpoint conditions) extend the address-expression
vocabulary with explicit, side-effect-free target-memory
dereference forms:

    u8(EXPR)    read 1 byte little-endian
    u16(EXPR)   read 2 bytes little-endian
    u32(EXPR)   read 4 bytes little-endian
    u64(EXPR)   read 8 bytes little-endian
    ptr(EXPR)   read pointer-sized (currently 8 bytes)
    poi(EXPR)   alias for ptr
    s8/s16/s32  signed forms, sign-extended to 64 bits

EXPR inside the parentheses uses the same address-expression
vocabulary and may itself contain another dereference, e.g.
`u32(ptr(rsp))`.  One outer `+`/`-` arithmetic step is
supported between value terms (`u32(counter)+1`,
`100+u32(counter)`, `ptr(rsp)+8`).  Whitespace is allowed
around the parentheses (`u32 ( counter )`).

Memory dereference expressions are explicit and read-only.
There is no C parser, no casts, no structs, no arrays, no
assignment, no boolean operators, no general parentheses,
and no memory writes through expressions.  Read failure
prints `cannot read uN at <addr>` and the enclosing command
or condition fails.

Symbols are refreshed automatically on `l`/`la` and after each
`lm`.  Use `sym -r` to force a refresh (useful after the
dynamic loader has mapped new shared libraries).

Tiny assembler operands for direct branches/calls use the same
expression resolver as commands, so `jmp foo`, `jz main+20`, and
`call module:symbol` work when the target is in rel8/rel32 range.
This is still a tiny assembler: no labels, no memory operands,
no relocation generation, no full x86 syntax.

Encoding sizes are deterministic, chosen by the mnemonic:

    jmp      = 5 bytes (E9 rel32)
    call     = 5 bytes (E8 rel32)
    jz/jnz   = 6 bytes (0F 84/85 rel32)
    jmp8     = 2 bytes (EB rel8)
    jz8/jnz8 = 2 bytes (74/75 rel8)
    nop/int3/ret = 1 byte

For far targets that cannot be reached with `rel32` (typically a
patch in the main module that needs to call into a DLL/.so), the
tiny assembler also accepts opt-in absolute pseudo-instructions:

    jmpabs  TARGET  = 13 bytes (49 BB <imm64> 41 FF E3)
    callabs TARGET  = 13 bytes (49 BB <imm64> 41 FF D3)
    jzabs   TARGET  = 15 bytes (75 0D 49 BB <imm64> 41 FF E3)
    jnzabs  TARGET  = 15 bytes (74 0D 49 BB <imm64> 41 FF E3)

`jeabs`/`jneabs` are aliases for `jzabs`/`jnzabs`.

Each absolute form is `movabs r11, TARGET` followed by an indirect
`jmp r11` or `call r11`; the conditional variants prepend an
inverted rel8 conditional jump that skips the 13-byte absolute
sequence.  They therefore **clobber `r11`** unconditionally — `r11`
is a volatile/caller-saved register in both System V AMD64 and
Windows x64 ABIs, but the user must still pick a patch site where
that is acceptable.  Absolute forms do not allocate trampolines,
preserve registers, relocate overwritten instructions, or create
PE/ELF relocations.

For `pa`, `len` must be at least the encoded instruction length;
shorter encodings are NOP-filled to `len`, longer ones are
rejected with `instruction length N exceeds patch length M`.
Examples:

    pa addr 5  jmp  symbol
    pa addr 5  call symbol
    pa addr 6  jz   symbol
    pa addr 2  jz8  symbol
    pa addr 13 jmpabs  module:symbol
    pa addr 13 callabs module:symbol
    pa addr 15 jzabs   module:symbol

Memory search (`s`) is chunked and bounded.  Region search
(`-a` / `-r` / `-m`) skips guard pages and silently skips
unreadable pages; it stops at a default result limit of 64
matches (override with `-limit N`).  Patterns are matched
literally only — there is no regex, wildcard, type-aware,
or disassembly-aware search.  Pointer-sized search (`-ptr`)
assumes a 64-bit target.

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

Breakpoint and watchpoint stop filters add hit counts, ignore
counts, and a tiny condition expression to existing software
breakpoints and hardware breakpoints/watchpoints.  Condition
grammar (no parentheses, no boolean operators, no memory
dereference):

    EXPR
    EXPR == EXPR
    EXPR != EXPR
    EXPR <  EXPR
    EXPR <= EXPR
    EXPR >  EXPR
    EXPR >= EXPR

Each `EXPR` is the same address-expression vocabulary used by
commands: numbers (default hex), `#decimal`, registers,
`module:symbol`, `module+offset`, `register+offset`.
Comparisons are unsigned 64-bit.  A bare `EXPR` is true when
its value is nonzero.

Hit counts increment for every zdbg-owned software breakpoint,
hardware execute breakpoint, and data watchpoint hit, including
hits suppressed by ignore count or condition.  Ignore counts
are consumed before conditions are evaluated.  Condition-false
hits auto-continue.  Software breakpoints still perform the
normal restore / single-step / reinsert dance before
continuing.  Clearing a breakpoint/watchpoint (`bc`, `hc`)
also clears its filter; disabling/enabling preserves it.  A
conservative auto-continue limit (100000 ignored/false hits per
`g`/`t`/`p` command) guards against pathological conditions on
hot code.  If condition parsing or evaluation fails the
debugger stops with a diagnostic instead of silently running.

Limitations: no boolean operators (`&&`, `||`), no parentheses
beyond the explicit dereference functions, no command lists,
no thread-specific conditions.  Conditions accept the same
target-memory dereference forms as `print`/`check expr`
(`u8/u16/u32/u64/ptr(EXPR)`).

Breakpoint action lists run a small bounded sequence of
commands when a hit passes the stop filter.  They are
deliberately not a scripting language: there are no variables,
loops, conditionals, macros, command-list nesting, or
thread-specific lists.  Each list is at most 8 lines of up to
160 characters.  The `silent` flag suppresses the normal stop
output for that hit so tracepoint-style "log and continue"
workflows produce only the lines they print themselves.  A
special `continue` (alias `cont`) action resumes the target
without recursively running `g`; software breakpoints reuse
the same restore / single-step / reinsert path as
ignored/condition-false hits.

Allowed action commands:

    r u d x addr bt lm sym th pl hl b hits check assert
    expect printf print eval silent continue cont

Disallowed in action lists (rejected with `action rejected:`):

    g t p l la ld k q source . bc bd be hb hw hc hd he
    cond ignore actions commands trace pa ij a e f m rf wf
    pw pu pr ps pf sig ex handle

`b` is allowed only as a list command; `b ADDR` would create a
new breakpoint mid-stop and is rejected.  Filters run before
actions: ignored and condition-false hits do not run actions.
Condition-evaluation failure stops the debugger and skips
actions.  An action that fails stops execution and returns
command failure regardless of any later `continue` action.

`trace b ADDR [TEXT...]` creates a software breakpoint with
`silent on` and a default action list of `printf TEXT` followed
by `continue`.  `trace h ID [TEXT...]` configures an existing
hardware breakpoint/watchpoint slot the same way.  When TEXT is
omitted a default `trace bp N hit` / `trace hwbp N hit` message
is used.  `printf TEXT...` prints the rest of the line followed
by a newline; the small backslash escapes `\n \t \r \\ \" \xNN`
are recognised and there are no format substitutions.

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

zdbg separates two axes:

* **OS backend** — owns process control, wait/stop handling, memory
  access, thread enumeration, and OS-specific signal/exception
  mechanics.  The supported backends are Linux ptrace and the
  Windows Debug API.
* **Target architecture** — owns instruction decoding, tiny patch
  assembly, software-breakpoint instruction bytes and length,
  software-breakpoint PC correction after a trap, abstract PC/SP/FP
  register access, command-level register print/get/set, and
  frame-pointer backtrace through `struct zarch_ops`.  x86-64 is
  the primary target architecture.  AArch64 has a phase-1 native
  Linux backend that supports launch/attach, memory I/O, integer
  register read/write through `zreg_file`, continue, single-step,
  and software breakpoints using `BRK #0`; a real AArch64
  disassembler, assembler, hardware breakpoints/watchpoints, and
  unwinder are still unimplemented and the corresponding ops fail
  cleanly with messages like "assembly not supported for
  architecture aarch64".

Generic command, run-control and breakpoint code reaches for
architecture-specific behavior only through the ops table on
`struct zdbg::arch`.  `cmd.c` no longer includes `zdbg_tinyasm.h`
or `zdbg_tinydis.h` — interactive `a`, `pa`, `ij`, `u`, `p`,
register print/get/set, and `bt` all dispatch through arch hooks.
The x86-only tinyasm/tinydis modules remain as the implementation
behind the x86-64 ops table.

The architecture is selected through `zdbg_select_arch_for_target()`
and mutated via `zdbg_set_arch()`, which keeps `d->arch_id`,
`d->arch`, and the breakpoint table in sync.  At launch (`l path
...`) the command layer also runs `zmachine_detect_file()` over
the executable on disk: ELF64 with `EM_X86_64`/`EM_AARCH64` and
PE32+ with `IMAGE_FILE_MACHINE_AMD64`/`IMAGE_FILE_MACHINE_ARM64`
are recognized.  The detected architecture is then matched against
`zdbg_backend_supports_arch()`: only the active backend's native
architecture is accepted.  Cross-architecture debugging is not
implemented, so an AArch64 ELF on an x86-64 host (or vice versa)
is rejected with an `unsupported target architecture: ... on this
backend/host` message.  32-bit ELF/PE (ELFCLASS32, PE32) and
unknown machine types are rejected with a clear message.
Attach (`la`) does not yet detect the target's machine type and
defaults to the active backend's native architecture; per-platform
attach detection is future work.

Register storage is still x86-64-shaped in the OS backends:
`struct zregs` is laid out for x86-64 and `ztarget_getregs` /
`ztarget_setregs` still operate on it.  On top of that storage
zdbg now exposes a generic integer register-file view
(`struct zreg_file` in `include/zdbg_regfile.h`) used by every
command and expression evaluator.  The register file consists of
per-architecture descriptors (name, width, role, writable flag)
plus current values, and resolves the architecture-neutral role
aliases `pc`, `sp`, and `fp` (and `ip`, `flags`) through the
canonical entry without duplicating state.  On x86-64:

    pc -> rip       sp -> rsp       fp -> rbp
    ip -> rip       flags -> rflags

The target boundary itself now exposes a generic register-file
API (`ztarget_get_regfile`, `ztarget_set_regfile`).  Command
code refreshes registers and pushes register writes through
those entry points; the Linux and Windows x86-64 backends
implement them by adapting the existing `struct zregs`
get/set path internally.  The legacy `ztarget_getregs` /
`ztarget_setregs` remain available for backend internals and
tests.

The expression evaluator and condition evaluator have register-
file-aware variants (`zexpr_eval_rf`, `zexpr_eval_symbols_rf`,
`zexpr_eval_value_rf`, `zcond_eval_rf`).  The legacy
`struct zregs *`-shaped APIs remain as compatibility wrappers
that build a temporary regfile internally.

Limitations of this phase:

* Only integer registers are represented; no SIMD/FPU/vector
  registers yet.
* On x86-64 backends the `struct zregs` shape is still used
  internally; the AArch64 path goes directly through
  `PTRACE_GETREGSET`/`PTRACE_SETREGSET` (`NT_PRSTATUS`) and
  populates `struct zreg_file` without a `struct zregs`
  intermediary.
* AArch64 support is native-host only: the Linux backend only
  debugs targets matching its native architecture.  Cross-arch
  debugging is not implemented.
* AArch64 `u` shows raw words (or "unsupported" diagnostics)
  because no AArch64 disassembler is wired up yet.  `a`/`pa`
  are unsupported on AArch64.  `hb`/`hw` are unsupported on
  AArch64 (DR0..DR7 are x86-64-only; AArch64 hardware debug
  registers are future work).
* Attach machine detection is not implemented; attach defaults
  to the backend's native architecture.

For portable scripts, prefer the role aliases:

    print pc          works on every supported arch
    check pc main     architecture-neutral PC check
    cond b 0 pc == main

The legacy x86-64 names (`rip`, `rsp`, etc.) and the
`check rip` form remain documented and supported on x86-64.

    include/        public headers
    src/            core implementation
        arch.c          architecture ops registry
        arch_x86_64.c   x86-64 ops (wraps tinyasm/tinydis)
        arch_aarch64.c  AArch64 stub ops
        regs.c          legacy x86-64 register helpers
        regfile.c       generic integer register-file view
        machine.c       ELF64/PE32+ executable machine detection
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

