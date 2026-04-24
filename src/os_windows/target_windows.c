/*
 * target_windows.c - Win32 Debug API backend for Windows x64.
 *
 * First real Windows backend.  Implements the zdbg_target.h
 * contract by driving CreateProcess(DEBUG_ONLY_THIS_PROCESS),
 * DebugActiveProcess, WaitForDebugEvent, ContinueDebugEvent,
 * ReadProcessMemory/WriteProcessMemory, FlushInstructionCache,
 * and GetThreadContext/SetThreadContext.
 *
 * Scope (see issues #24, #28, #29):
 *   - launch, attach, detach, kill
 *   - wait with conservative event mapping
 *   - continue / single-step (trap flag)
 *   - memory read/write/flush_icache (all-or-nothing)
 *   - x64 register get/set via CONTEXT
 *   - basic thread list/select from debug events
 *   - software breakpoints via EXCEPTION_BREAKPOINT mapping
 *   - module maps / PE export symbols from debug events
 *   - hardware breakpoints/watchpoints via CONTEXT_DEBUG_REGISTERS
 *
 * Not in scope:
 *   - PDB/DIA SDK / CodeView / private PE symbols / DWARF
 *   - Windows exception-policy UI / signal-style handle table
 *   - WOW64 / 32-bit x86 target support / remote debugging
 *   - thread-specific hwbp UI / per-thread watchpoint UI
 *
 * <windows.h> must not be included anywhere else in the tree.
 */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zdbg_target.h"
#include "zdbg_maps.h"
#include "zdbg_symbols.h"

/* ---------------- private state ---------------- */

#define ZW_MAX_THREADS ZDBG_MAX_THREADS
#define ZW_MAX_MODULES 256
#define ZW_MODULE_NAME_MAX 260
/* Reasonable ceiling for IMAGE_DOS_HEADER.e_lfanew to reject
 * corrupt PE headers without locking us out of large real-world
 * images. */
#define ZW_PE_MAX_E_LFANEW 0x100000

struct zw_thread {
	DWORD tid;
	HANDLE handle;
	enum zthread_state state;
};

struct zw_module {
	uint64_t base;
	uint64_t size;
	char path[ZW_MODULE_NAME_MAX];
};

struct zw_target {
	DWORD pid;
	HANDLE process;
	int launched;
	int attached;
	int exited;
	DWORD exit_code;

	DEBUG_EVENT last_event;
	int have_event;		/* nonzero while last_event is pending */
	DWORD continue_status;	/* DBG_CONTINUE or DBG_EXCEPTION_NOT_HANDLED */
	int got_initial;	/* first breakpoint has been reported */

	DWORD current_tid;
	struct zw_thread threads[ZW_MAX_THREADS];
	int nthreads;		/* high-water slot count */

	struct zw_module modules[ZW_MAX_MODULES];
	int nmodules;		/* high-water slot count */

	/*
	 * TID that the debugger explicitly asked to single-step
	 * via ztarget_windows_singlestep(), or 0 when no step is
	 * expected.  Used by the event loop to distinguish a
	 * TF-driven EXCEPTION_SINGLE_STEP (which should map to
	 * ZSTOP_SINGLESTEP) from a hardware-debug-register trap
	 * (which should map to ZSTOP_BREAKPOINT so the generic
	 * hwbp layer can claim it).
	 */
	DWORD singlestep_tid;
};

static struct zw_target *
zw_get(struct ztarget *t)
{
	if (t == NULL)
		return NULL;
	return (struct zw_target *)t->os;
}

static struct zw_target *
zw_alloc(struct ztarget *t)
{
	struct zw_target *wt;

	if (t == NULL)
		return NULL;
	wt = (struct zw_target *)calloc(1, sizeof(*wt));
	if (wt == NULL)
		return NULL;
	wt->continue_status = DBG_CONTINUE;
	t->os = wt;
	return wt;
}

static void
zw_free(struct ztarget *t)
{
	struct zw_target *wt;
	int i;

	if (t == NULL || t->os == NULL)
		return;
	wt = (struct zw_target *)t->os;
	for (i = 0; i < wt->nthreads; i++) {
		if (wt->threads[i].handle != NULL) {
			CloseHandle(wt->threads[i].handle);
			wt->threads[i].handle = NULL;
		}
	}
	if (wt->process != NULL) {
		CloseHandle(wt->process);
		wt->process = NULL;
	}
	free(wt);
	t->os = NULL;
}

/* ---------------- thread table helpers ---------------- */

static struct zw_thread *
zw_find(struct zw_target *wt, DWORD tid)
{
	int i;

	for (i = 0; i < wt->nthreads; i++) {
		if (wt->threads[i].tid == tid)
			return &wt->threads[i];
	}
	return NULL;
}

static struct zw_thread *
zw_add(struct zw_target *wt, DWORD tid, HANDLE h)
{
	struct zw_thread *th;
	int i;

	th = zw_find(wt, tid);
	if (th != NULL) {
		/* Replace handle if a new one was provided. */
		if (h != NULL && th->handle != h) {
			if (th->handle != NULL)
				CloseHandle(th->handle);
			th->handle = h;
		}
		th->state = ZTHREAD_STOPPED;
		return th;
	}
	/* Reuse an empty slot first. */
	for (i = 0; i < wt->nthreads; i++) {
		if (wt->threads[i].tid == 0) {
			th = &wt->threads[i];
			memset(th, 0, sizeof(*th));
			th->tid = tid;
			th->handle = h;
			th->state = ZTHREAD_STOPPED;
			return th;
		}
	}
	if (wt->nthreads >= ZW_MAX_THREADS) {
		/* Table full: caller must close handle. */
		return NULL;
	}
	th = &wt->threads[wt->nthreads++];
	memset(th, 0, sizeof(*th));
	th->tid = tid;
	th->handle = h;
	th->state = ZTHREAD_STOPPED;
	return th;
}

static void
zw_remove(struct zw_target *wt, DWORD tid)
{
	struct zw_thread *th = zw_find(wt, tid);
	if (th == NULL)
		return;
	if (th->handle != NULL) {
		CloseHandle(th->handle);
		th->handle = NULL;
	}
	th->state = ZTHREAD_EXITED;
	/* keep slot occupied with tid so callers can still see exited */
}

static HANDLE
zw_current_handle(struct zw_target *wt)
{
	struct zw_thread *th;
	if (wt == NULL)
		return NULL;
	th = zw_find(wt, wt->current_tid);
	if (th == NULL)
		return NULL;
	return th->handle;
}

/* ---------------- module table helpers ---------------- */

static struct zw_module *
zw_mod_find(struct zw_target *wt, uint64_t base)
{
	int i;
	for (i = 0; i < wt->nmodules; i++) {
		if (wt->modules[i].base == base && wt->modules[i].size != 0)
			return &wt->modules[i];
	}
	return NULL;
}

/*
 * Resolve the path of a module from its hFile handle.  Uses
 * GetFinalPathNameByHandleA which is available since Vista.  On
 * failure leaves out[0] = 0.  `\\?\C:\...` -> `C:\...`.
 */
static void
zw_path_from_handle(HANDLE hFile, char *out, size_t cap)
{
	DWORD n;

	if (cap == 0)
		return;
	out[0] = 0;
	if (hFile == NULL || hFile == INVALID_HANDLE_VALUE)
		return;
	n = GetFinalPathNameByHandleA(hFile, out, (DWORD)cap, 0);
	if (n == 0 || n >= cap) {
		out[0] = 0;
		return;
	}
	/* Strip leading \\?\ or \\?\UNC\. */
	if (n >= 4 && out[0] == '\\' && out[1] == '\\' &&
	    out[2] == '?' && out[3] == '\\') {
		memmove(out, out + 4, (size_t)(n - 4 + 1));
	}
}

/*
 * Read PE headers from target memory at `base` and return
 * SizeOfImage on success, or 0 if headers look invalid.  64-bit
 * PE only.  Defensive against partial reads and bad fields.
 */
static uint64_t
zw_read_size_of_image(struct zw_target *wt, uint64_t base)
{
	IMAGE_DOS_HEADER dos;
	IMAGE_NT_HEADERS64 nt;
	SIZE_T got = 0;
	LONG e_lfanew;

	if (wt == NULL || wt->process == NULL)
		return 0;
	if (!ReadProcessMemory(wt->process, (LPCVOID)(uintptr_t)base,
	    &dos, sizeof(dos), &got) || got != sizeof(dos))
		return 0;
	if (dos.e_magic != IMAGE_DOS_SIGNATURE)
		return 0;
	e_lfanew = dos.e_lfanew;
	if (e_lfanew <= 0 || e_lfanew > ZW_PE_MAX_E_LFANEW)
		return 0;
	if (!ReadProcessMemory(wt->process,
	    (LPCVOID)(uintptr_t)(base + (uint64_t)e_lfanew),
	    &nt, sizeof(nt), &got) || got != sizeof(nt))
		return 0;
	if (nt.Signature != IMAGE_NT_SIGNATURE)
		return 0;
	if (nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return 0;
	if (nt.OptionalHeader.SizeOfImage == 0)
		return 0;
	return (uint64_t)nt.OptionalHeader.SizeOfImage;
}

/*
 * Record a module load.  base must be nonzero.  hFile may be
 * NULL.  If PE size cannot be determined, fall back to one page
 * so `lm` still shows the base; better to see something than
 * nothing.  Caller is responsible for closing hFile.
 */
static void
zw_module_add(struct zw_target *wt, uint64_t base, HANDLE hFile)
{
	struct zw_module *mod;
	uint64_t size;
	int i;

	if (wt == NULL || base == 0)
		return;

	/* Replace existing slot with same base, else pick free slot. */
	mod = zw_mod_find(wt, base);
	if (mod == NULL) {
		for (i = 0; i < wt->nmodules; i++) {
			if (wt->modules[i].size == 0 &&
			    wt->modules[i].base == 0) {
				mod = &wt->modules[i];
				break;
			}
		}
	}
	if (mod == NULL) {
		if (wt->nmodules >= ZW_MAX_MODULES)
			return;
		mod = &wt->modules[wt->nmodules++];
	}
	memset(mod, 0, sizeof(*mod));
	mod->base = base;

	size = zw_read_size_of_image(wt, base);
	if (size == 0)
		size = 0x1000;	/* best-effort placeholder */
	mod->size = size;

	zw_path_from_handle(hFile, mod->path, sizeof(mod->path));
	if (mod->path[0] == 0) {
		/* Synthetic fallback name so lm/sym show something. */
		snprintf(mod->path, sizeof(mod->path),
		    "module@%016llx", (unsigned long long)base);
	}
}

static void
zw_module_remove(struct zw_target *wt, uint64_t base)
{
	struct zw_module *mod;

	if (wt == NULL)
		return;
	mod = zw_mod_find(wt, base);
	if (mod == NULL)
		return;
	memset(mod, 0, sizeof(*mod));
}

/* ---------------- PE export parsing (from target memory) -------- */

#define ZW_PE_MAX_EXPORTS 65536		/* generous cap vs. corrupt PE */
#define ZW_PE_MAX_NAMELEN 512

/*
 * Read a NUL-terminated ASCII string of up to `cap-1` bytes from
 * target memory.  Returns bytes copied (excluding NUL) or -1 on
 * failure.  Reads in chunks to avoid reading past image bounds.
 */
static int
zw_read_cstr(struct zw_target *wt, uint64_t addr, char *out, size_t cap)
{
	size_t n = 0;

	if (cap == 0)
		return -1;
	out[0] = 0;
	while (n + 1 < cap) {
		SIZE_T got = 0;
		size_t chunk = 64;
		char tmp[64];
		size_t i;

		if (chunk > cap - 1 - n)
			chunk = cap - 1 - n;
		if (!ReadProcessMemory(wt->process,
		    (LPCVOID)(uintptr_t)(addr + (uint64_t)n),
		    tmp, chunk, &got) || got == 0)
			return -1;
		for (i = 0; i < got; i++) {
			if (tmp[i] == 0) {
				out[n] = 0;
				return (int)n;
			}
			out[n++] = tmp[i];
			if (n + 1 >= cap) {
				out[n] = 0;
				return (int)n;
			}
		}
	}
	out[n] = 0;
	return (int)n;
}

/*
 * Load PE exports for module `mod` into st.  Skips ordinal-only
 * and forwarded exports.  Defensive against corrupt headers.
 */
static void
zw_load_exports(struct zw_target *wt, const struct zw_module *mod,
    struct zsym_table *st)
{
	IMAGE_DOS_HEADER dos;
	IMAGE_NT_HEADERS64 nt;
	IMAGE_DATA_DIRECTORY dir;
	IMAGE_EXPORT_DIRECTORY ex;
	SIZE_T got = 0;
	uint64_t base;
	uint64_t dir_start;
	uint64_t dir_end;
	DWORD nnames;
	DWORD i;
	DWORD *name_rvas = NULL;
	WORD *name_ords = NULL;
	DWORD *func_rvas = NULL;
	DWORD nfuncs;

	if (wt == NULL || mod == NULL || st == NULL)
		return;
	if (wt->process == NULL)
		return;
	base = mod->base;

	if (!ReadProcessMemory(wt->process, (LPCVOID)(uintptr_t)base,
	    &dos, sizeof(dos), &got) || got != sizeof(dos))
		return;
	if (dos.e_magic != IMAGE_DOS_SIGNATURE)
		return;
	if (dos.e_lfanew <= 0 || dos.e_lfanew > ZW_PE_MAX_E_LFANEW)
		return;
	if (!ReadProcessMemory(wt->process,
	    (LPCVOID)(uintptr_t)(base + (uint64_t)dos.e_lfanew),
	    &nt, sizeof(nt), &got) || got != sizeof(nt))
		return;
	if (nt.Signature != IMAGE_NT_SIGNATURE)
		return;
	if (nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return;
	if (IMAGE_DIRECTORY_ENTRY_EXPORT >=
	    nt.OptionalHeader.NumberOfRvaAndSizes)
		return;
	dir = nt.OptionalHeader.DataDirectory[
	    IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (dir.VirtualAddress == 0 || dir.Size < sizeof(ex))
		return;
	dir_start = base + (uint64_t)dir.VirtualAddress;
	dir_end = dir_start + (uint64_t)dir.Size;
	if (!ReadProcessMemory(wt->process,
	    (LPCVOID)(uintptr_t)dir_start,
	    &ex, sizeof(ex), &got) || got != sizeof(ex))
		return;

	nnames = ex.NumberOfNames;
	nfuncs = ex.NumberOfFunctions;
	if (nnames == 0 || nnames > ZW_PE_MAX_EXPORTS)
		return;
	if (nfuncs == 0 || nfuncs > ZW_PE_MAX_EXPORTS)
		return;
	if (ex.AddressOfNames == 0 || ex.AddressOfNameOrdinals == 0 ||
	    ex.AddressOfFunctions == 0)
		return;

	name_rvas = (DWORD *)malloc(sizeof(DWORD) * (size_t)nnames);
	name_ords = (WORD *)malloc(sizeof(WORD) * (size_t)nnames);
	func_rvas = (DWORD *)malloc(sizeof(DWORD) * (size_t)nfuncs);
	if (name_rvas == NULL || name_ords == NULL || func_rvas == NULL)
		goto done;

	if (!ReadProcessMemory(wt->process,
	    (LPCVOID)(uintptr_t)(base + (uint64_t)ex.AddressOfNames),
	    name_rvas, sizeof(DWORD) * (size_t)nnames, &got) ||
	    got != sizeof(DWORD) * (size_t)nnames)
		goto done;
	if (!ReadProcessMemory(wt->process,
	    (LPCVOID)(uintptr_t)(base +
	    (uint64_t)ex.AddressOfNameOrdinals),
	    name_ords, sizeof(WORD) * (size_t)nnames, &got) ||
	    got != sizeof(WORD) * (size_t)nnames)
		goto done;
	if (!ReadProcessMemory(wt->process,
	    (LPCVOID)(uintptr_t)(base + (uint64_t)ex.AddressOfFunctions),
	    func_rvas, sizeof(DWORD) * (size_t)nfuncs, &got) ||
	    got != sizeof(DWORD) * (size_t)nfuncs)
		goto done;

	for (i = 0; i < nnames; i++) {
		WORD ord;
		DWORD frva;
		char name[ZW_PE_MAX_NAMELEN];
		zaddr_t fn_addr;
		struct zsym *out;
		size_t nl;

		if (st->count >= ZDBG_MAX_SYMBOLS) {
			st->truncated = 1;
			break;
		}
		ord = name_ords[i];
		if ((DWORD)ord >= nfuncs)
			continue;
		frva = func_rvas[ord];
		if (frva == 0)
			continue;
		/* Forwarded exports: function RVA points inside the
		 * export directory and is actually a string like
		 * "KERNELBASE.CreateFileW".  Skip them. */
		{
			uint64_t fva = base + (uint64_t)frva;
			if (fva >= dir_start && fva < dir_end)
				continue;
		}
		if (name_rvas[i] == 0)
			continue;
		if (zw_read_cstr(wt,
		    base + (uint64_t)name_rvas[i], name,
		    sizeof(name)) <= 0)
			continue;

		fn_addr = (zaddr_t)(base + (uint64_t)frva);

		out = &st->syms[st->count];
		memset(out, 0, sizeof(*out));
		out->addr = fn_addr;
		out->size = 0;
		out->type = 'T';
		out->bind = 'G';
		nl = strlen(name);
		if (nl >= ZDBG_SYM_NAME_MAX)
			nl = ZDBG_SYM_NAME_MAX - 1;
		memcpy(out->name, name, nl);
		out->name[nl] = 0;
		nl = strlen(mod->path);
		if (nl >= ZDBG_SYM_MODULE_MAX)
			nl = ZDBG_SYM_MODULE_MAX - 1;
		memcpy(out->module, mod->path, nl);
		out->module[nl] = 0;
		st->count++;
	}

done:
	if (name_rvas) free(name_rvas);
	if (name_ords) free(name_ords);
	if (func_rvas) free(func_rvas);
}

/* ---------------- public fill helpers ---------------- */

int
ztarget_windows_fill_maps(struct ztarget *t, struct zmap_table *mt)
{
	struct zw_target *wt = zw_get(t);
	int i;

	if (wt == NULL || mt == NULL)
		return -1;
	mt->count = 0;
	mt->truncated = 0;
	for (i = 0; i < wt->nmodules; i++) {
		const struct zw_module *mod = &wt->modules[i];
		struct zmap *m;
		size_t nlen;

		if (mod->base == 0 || mod->size == 0)
			continue;
		if (mt->count >= ZDBG_MAX_MAPS) {
			mt->truncated = 1;
			break;
		}
		m = &mt->maps[mt->count++];
		memset(m, 0, sizeof(*m));
		m->start = (zaddr_t)mod->base;
		m->end = (zaddr_t)(mod->base + mod->size);
		m->offset = 0;
		memcpy(m->perms, "r-xp", 5);
		nlen = strlen(mod->path);
		if (nlen >= ZDBG_MAP_NAME_MAX)
			nlen = ZDBG_MAP_NAME_MAX - 1;
		memcpy(m->name, mod->path, nlen);
		m->name[nlen] = 0;
		m->raw_file_offset_valid = 0;
		m->kind = ZMAP_KIND_MODULE;
		m->mem_type = ZMAP_MEM_IMAGE;
	}
	return 0;
}

/* ---- VirtualQueryEx region enumeration ---- */

void
zmaps_protect_to_perms(uint32_t protect, char out[5])
{
	uint32_t base;
	int guard;

	guard = (protect & PAGE_GUARD) != 0;
	/* Drop modifier bits before classifying the access mask. */
	base = protect & ~(uint32_t)(PAGE_GUARD | PAGE_NOCACHE |
	    PAGE_WRITECOMBINE);

	out[0] = '-';
	out[1] = '-';
	out[2] = '-';
	out[3] = guard ? 'g' : 'p';
	out[4] = 0;

	switch (base) {
	case PAGE_NOACCESS:
		break;
	case PAGE_READONLY:
		out[0] = 'r';
		break;
	case PAGE_READWRITE:
	case PAGE_WRITECOPY:
		out[0] = 'r';
		out[1] = 'w';
		break;
	case PAGE_EXECUTE:
		out[2] = 'x';
		break;
	case PAGE_EXECUTE_READ:
		out[0] = 'r';
		out[2] = 'x';
		break;
	case PAGE_EXECUTE_READWRITE:
	case PAGE_EXECUTE_WRITECOPY:
		out[0] = 'r';
		out[1] = 'w';
		out[2] = 'x';
		break;
	default:
		break;
	}
}

/* Find a known module whose image range contains addr.  Returns
 * the module index or -1. */
static int
zw_find_module_for_addr(const struct zw_target *wt, uint64_t addr)
{
	int i;

	for (i = 0; i < wt->nmodules; i++) {
		const struct zw_module *mod = &wt->modules[i];
		if (mod->base == 0 || mod->size == 0)
			continue;
		if (addr >= mod->base && addr < mod->base + mod->size)
			return i;
	}
	return -1;
}

int
ztarget_windows_fill_regions(struct ztarget *t, struct zmap_table *mt)
{
	struct zw_target *wt = zw_get(t);
	HANDLE proc;
	SYSTEM_INFO si;
	uint64_t addr;
	uint64_t maxaddr;

	if (wt == NULL || mt == NULL)
		return -1;
	mt->count = 0;
	mt->truncated = 0;

	proc = wt->process;
	if (proc == NULL)
		return -1;

	GetNativeSystemInfo(&si);
	addr = (uint64_t)(uintptr_t)si.lpMinimumApplicationAddress;
	maxaddr = (uint64_t)(uintptr_t)si.lpMaximumApplicationAddress;

	for (;;) {
		MEMORY_BASIC_INFORMATION mbi;
		SIZE_T qrc;
		uint64_t base;
		uint64_t next;

		if (addr > maxaddr)
			break;

		memset(&mbi, 0, sizeof(mbi));
		qrc = VirtualQueryEx(proc, (LPCVOID)(uintptr_t)addr,
		    &mbi, sizeof(mbi));
		if (qrc == 0) {
			/* Skip past this page and keep going; user
			 * regions can have unmappable holes. */
			next = addr + (uint64_t)si.dwPageSize;
			if (next <= addr)
				break;
			addr = next;
			continue;
		}

		base = (uint64_t)(uintptr_t)mbi.BaseAddress;
		next = base + (uint64_t)mbi.RegionSize;
		if (next <= base) {
			/* No progress: bail to avoid infinite loop. */
			break;
		}

		if (mbi.State == MEM_COMMIT) {
			struct zmap *m;
			int modidx;
			size_t nlen;
			const char *name;

			if (mt->count >= ZDBG_MAX_MAPS) {
				mt->truncated = 1;
				break;
			}
			m = &mt->maps[mt->count++];
			memset(m, 0, sizeof(*m));
			m->start = (zaddr_t)base;
			m->end = (zaddr_t)next;
			m->offset = 0;
			zmaps_protect_to_perms((uint32_t)mbi.Protect,
			    m->perms);
			m->protect = (uint32_t)mbi.Protect;
			m->state = (uint32_t)mbi.State;
			m->kind = ZMAP_KIND_REGION;
			m->raw_file_offset_valid = 0;

			switch (mbi.Type) {
			case MEM_IMAGE:
				m->mem_type = ZMAP_MEM_IMAGE;
				modidx = zw_find_module_for_addr(wt, base);
				if (modidx >= 0) {
					name = wt->modules[modidx].path;
				} else {
					name = "[image]";
				}
				break;
			case MEM_MAPPED:
				m->mem_type = ZMAP_MEM_MAPPED;
				name = "[mapped]";
				break;
			case MEM_PRIVATE:
				m->mem_type = ZMAP_MEM_PRIVATE;
				if (mbi.Protect & PAGE_GUARD)
					name = "[private guard]";
				else
					name = "[private]";
				break;
			default:
				m->mem_type = ZMAP_MEM_UNKNOWN;
				name = "";
				break;
			}
			nlen = strlen(name);
			if (nlen >= ZDBG_MAP_NAME_MAX)
				nlen = ZDBG_MAP_NAME_MAX - 1;
			memcpy(m->name, name, nlen);
			m->name[nlen] = 0;
		}

		addr = next;
	}
	return 0;
}

int
ztarget_windows_fill_syms(struct ztarget *t, struct zsym_table *st)
{
	struct zw_target *wt = zw_get(t);
	int i;
	int scanned = 0;

	if (wt == NULL || st == NULL)
		return -1;
	for (i = 0; i < wt->nmodules; i++) {
		const struct zw_module *mod = &wt->modules[i];
		if (mod->base == 0 || mod->size == 0)
			continue;
		zw_load_exports(wt, mod, st);
		scanned++;
		if (st->count >= ZDBG_MAX_SYMBOLS) {
			st->truncated = 1;
			break;
		}
	}
	return scanned;
}

/* ---------------- command-line quoting ---------------- */

/*
 * Build a Windows command line from argv.  Follows the common
 * CommandLineToArgvW quoting: wrap arguments containing spaces,
 * tabs or quotes in double-quotes, escape embedded backslashes
 * that precede a quote, and escape embedded quotes with a
 * backslash.  argv[0] gets the same treatment so a path with
 * spaces still works.
 *
 * Returns a malloc()d buffer on success, NULL on failure.  The
 * original argv is not modified.
 */
static char *
zw_build_cmdline(int argc, char **argv)
{
	size_t cap = 64;
	size_t len = 0;
	char *buf;
	int i;

	if (argc <= 0 || argv == NULL || argv[0] == NULL)
		return NULL;

	buf = (char *)malloc(cap);
	if (buf == NULL)
		return NULL;
	buf[0] = 0;

	for (i = 0; i < argc; i++) {
		const char *s = argv[i];
		int needs_quote;
		size_t j;
		size_t extra;

		if (s == NULL)
			s = "";
		needs_quote = (s[0] == 0);
		for (j = 0; s[j] != 0; j++) {
			char c = s[j];
			if (c == ' ' || c == '\t' || c == '"')
				needs_quote = 1;
		}
		/* Worst case: every char may double, plus 2 quotes + space + NUL */
		extra = (strlen(s) * 2) + 4;
		while (len + extra + 1 > cap) {
			size_t ncap = cap * 2;
			char *nbuf = (char *)realloc(buf, ncap);
			if (nbuf == NULL) {
				free(buf);
				return NULL;
			}
			buf = nbuf;
			cap = ncap;
		}
		if (i > 0)
			buf[len++] = ' ';
		if (needs_quote)
			buf[len++] = '"';
		{
			size_t k = 0;
			while (s[k] != 0) {
				/* Count run of backslashes. */
				size_t bs = 0;
				while (s[k] == '\\') {
					bs++;
					k++;
				}
				if (s[k] == 0) {
					/*
					 * Trailing backslashes: if quoted,
					 * double them so the closing quote
					 * is not escaped.
					 */
					size_t m;
					size_t mul = needs_quote ? 2 : 1;
					for (m = 0; m < bs * mul; m++)
						buf[len++] = '\\';
					break;
				}
				if (s[k] == '"') {
					size_t m;
					/* Double backslashes + escape quote. */
					for (m = 0; m < bs * 2; m++)
						buf[len++] = '\\';
					buf[len++] = '\\';
					buf[len++] = '"';
					k++;
				} else {
					size_t m;
					for (m = 0; m < bs; m++)
						buf[len++] = '\\';
					buf[len++] = s[k++];
				}
			}
		}
		if (needs_quote)
			buf[len++] = '"';
	}
	buf[len] = 0;
	return buf;
}

/* ---------------- exception mapping ---------------- */

/*
 * Check whether DR6 on the event thread indicates a hardware
 * debug-register trap, i.e. any of B0..B3 is set.  Returns 1
 * when a hardware trap bit is set, 0 otherwise, -1 when the
 * context could not be read.  The DR6 value is intentionally
 * not cleared here: the generic hwbp layer is responsible for
 * clearing DR6 via the debug-register API so it can correlate
 * the bit with its own slot table first.
 */
static int
zw_event_dr6_hw_trap(struct zw_target *wt, DWORD tid)
{
	struct zw_thread *th;
	CONTEXT ctx;

#if !defined(_M_X64) && !defined(_M_AMD64) && !defined(__x86_64__)
	(void)wt; (void)tid;
	return -1;
#else
	if (wt == NULL)
		return -1;
	th = zw_find(wt, tid);
	if (th == NULL || th->handle == NULL)
		return -1;
	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (!GetThreadContext(th->handle, &ctx))
		return -1;
	if ((ctx.Dr6 & 0xfULL) != 0)
		return 1;
	return 0;
#endif
}

/*
 * Map a first-chance exception into a zstop reason and decide
 * the default continue status.  For breakpoint and single-step
 * traps that zdbg drives we always return DBG_CONTINUE so the
 * OS does not deliver them to the target.  For real exceptions
 * (access violation, illegal instruction, etc.) we keep the
 * conservative "not handled" default so `g` lets the target
 * see/crash as it would outside the debugger.
 */
static void
zw_map_exception(struct zw_target *wt,
    const EXCEPTION_DEBUG_INFO *ex, struct zstop *st)
{
	DWORD code = ex->ExceptionRecord.ExceptionCode;
	DWORD tid = wt->last_event.dwThreadId;
	uint64_t addr = (uint64_t)(uintptr_t)
	    ex->ExceptionRecord.ExceptionAddress;

	st->addr = addr;
	st->code = (int)code;
	st->first_chance = ex->dwFirstChance ? 1 : 0;

	switch (code) {
	case EXCEPTION_BREAKPOINT:
		if (!wt->got_initial) {
			wt->got_initial = 1;
			st->reason = ZSTOP_INITIAL;
			st->code = 0;
		} else {
			st->reason = ZSTOP_BREAKPOINT;
			st->code = 0;
		}
		wt->continue_status = DBG_CONTINUE;
		return;
	case EXCEPTION_SINGLE_STEP: {
		/*
		 * Hardware breakpoints/watchpoints also arrive here
		 * on x86.  Distinguish them from a normal TF-driven
		 * step using the singlestep_tid expectation flag and
		 * DR6.  If the stop is on a thread we asked to step
		 * and DR6 shows no B0..B3 set, it is a genuine
		 * single-step.  Otherwise treat it as a breakpoint-
		 * like stop so the command layer routes it through
		 * the generic hwbp handler.
		 */
		int is_hw = zw_event_dr6_hw_trap(wt, tid);
		int expected_step = (wt->singlestep_tid != 0 &&
		    wt->singlestep_tid == tid);
		if (expected_step)
			wt->singlestep_tid = 0;
		if (is_hw == 1)
			st->reason = ZSTOP_BREAKPOINT;
		else
			st->reason = ZSTOP_SINGLESTEP;
		st->code = 0;
		wt->continue_status = DBG_CONTINUE;
		return;
	}
	default:
		st->reason = ZSTOP_EXCEPTION;
		wt->continue_status = DBG_EXCEPTION_NOT_HANDLED;
		return;
	}
}

/* ---------------- event dispatcher ---------------- */

/*
 * Dispatch a single DEBUG_EVENT already stored in wt->last_event.
 *
 * Returns:
 *   1  user-visible stop filled into *st; leave event pending
 *   0  internal event; caller should ContinueDebugEvent and loop
 *  -1  hard error
 */
static int
zw_handle_event(struct zw_target *wt, struct zstop *st)
{
	const DEBUG_EVENT *ev = &wt->last_event;

	st->tid = (uint64_t)ev->dwThreadId;

	switch (ev->dwDebugEventCode) {
	case CREATE_PROCESS_DEBUG_EVENT: {
		const CREATE_PROCESS_DEBUG_INFO *ci =
		    &ev->u.CreateProcessInfo;
		if (wt->process == NULL && ci->hProcess != NULL)
			wt->process = ci->hProcess;
		if (ci->hThread != NULL)
			(void)zw_add(wt, ev->dwThreadId, ci->hThread);
		if (ci->lpBaseOfImage != NULL) {
			zw_module_add(wt,
			    (uint64_t)(uintptr_t)ci->lpBaseOfImage,
			    ci->hFile);
		}
		if (ci->hFile != NULL)
			CloseHandle(ci->hFile);
		wt->continue_status = DBG_CONTINUE;
		return 0;
	}
	case CREATE_THREAD_DEBUG_EVENT: {
		const CREATE_THREAD_DEBUG_INFO *ci =
		    &ev->u.CreateThread;
		(void)zw_add(wt, ev->dwThreadId, ci->hThread);
		wt->continue_status = DBG_CONTINUE;
		return 0;
	}
	case EXIT_THREAD_DEBUG_EVENT:
		zw_remove(wt, ev->dwThreadId);
		wt->continue_status = DBG_CONTINUE;
		return 0;
	case EXIT_PROCESS_DEBUG_EVENT:
		wt->exited = 1;
		wt->exit_code = ev->u.ExitProcess.dwExitCode;
		st->reason = ZSTOP_EXIT;
		st->code = (int)ev->u.ExitProcess.dwExitCode;
		st->addr = 0;
		wt->continue_status = DBG_CONTINUE;
		return 1;
	case LOAD_DLL_DEBUG_EVENT:
		if (ev->u.LoadDll.lpBaseOfDll != NULL) {
			zw_module_add(wt,
			    (uint64_t)(uintptr_t)
			    ev->u.LoadDll.lpBaseOfDll,
			    ev->u.LoadDll.hFile);
		}
		if (ev->u.LoadDll.hFile != NULL)
			CloseHandle(ev->u.LoadDll.hFile);
		wt->continue_status = DBG_CONTINUE;
		return 0;
	case UNLOAD_DLL_DEBUG_EVENT:
		if (ev->u.UnloadDll.lpBaseOfDll != NULL) {
			zw_module_remove(wt,
			    (uint64_t)(uintptr_t)
			    ev->u.UnloadDll.lpBaseOfDll);
		}
		wt->continue_status = DBG_CONTINUE;
		return 0;
	case OUTPUT_DEBUG_STRING_EVENT:
		wt->continue_status = DBG_CONTINUE;
		return 0;
	case RIP_EVENT:
		/* Treat as non-fatal: continue. */
		wt->continue_status = DBG_CONTINUE;
		return 0;
	case EXCEPTION_DEBUG_EVENT:
		zw_map_exception(wt, &ev->u.Exception, st);
		return 1;
	default:
		wt->continue_status = DBG_CONTINUE;
		return 0;
	}
}

/* ---------------- wait ---------------- */

int
ztarget_windows_wait(struct ztarget *t, struct zstop *st)
{
	struct zw_target *wt = zw_get(t);
	int rc;

	if (wt == NULL || st == NULL)
		return -1;
	memset(st, 0, sizeof(*st));

	/*
	 * If a previous event is still pending it means the caller
	 * forgot to continue it.  Continue internally to keep the
	 * debuggee moving rather than hanging.
	 */
	if (wt->have_event) {
		(void)ContinueDebugEvent(wt->last_event.dwProcessId,
		    wt->last_event.dwThreadId, wt->continue_status);
		wt->have_event = 0;
	}

	for (;;) {
		memset(&wt->last_event, 0, sizeof(wt->last_event));
		wt->continue_status = DBG_CONTINUE;
		if (!WaitForDebugEvent(&wt->last_event, INFINITE)) {
			st->reason = ZSTOP_ERROR;
			return -1;
		}

		rc = zw_handle_event(wt, st);
		if (rc < 0) {
			st->reason = ZSTOP_ERROR;
			(void)ContinueDebugEvent(wt->last_event.dwProcessId,
			    wt->last_event.dwThreadId, DBG_CONTINUE);
			return -1;
		}
		if (rc == 1) {
			/* User-visible stop: keep event pending. */
			wt->have_event = 1;
			wt->current_tid = wt->last_event.dwThreadId;
			if (st->reason == ZSTOP_EXIT) {
				/*
				 * Windows still expects a final
				 * ContinueDebugEvent for the exit
				 * event so the debug session closes
				 * cleanly.
				 */
				(void)ContinueDebugEvent(
				    wt->last_event.dwProcessId,
				    wt->last_event.dwThreadId,
				    DBG_CONTINUE);
				wt->have_event = 0;
				t->state = ZTARGET_EXITED;
				t->tid = st->tid;
				return 0;
			}
			/* Fill RIP from selected-thread context. */
			{
				HANDLE h = zw_current_handle(wt);
				if (h != NULL) {
					CONTEXT ctx;
					memset(&ctx, 0, sizeof(ctx));
					ctx.ContextFlags = CONTEXT_CONTROL;
					if (GetThreadContext(h, &ctx))
						st->addr =
						    (uint64_t)ctx.Rip;
				}
			}
			t->state = ZTARGET_STOPPED;
			t->tid = st->tid;
			return 0;
		}
		/* Internal event: continue and keep waiting. */
		(void)ContinueDebugEvent(wt->last_event.dwProcessId,
		    wt->last_event.dwThreadId, wt->continue_status);
	}
}

/* ---------------- launch ---------------- */

int
ztarget_windows_launch(struct ztarget *t, int argc, char **argv)
{
	struct zw_target *wt;
	char *cmdline;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	BOOL ok;
	struct zstop st;

	if (t == NULL || argc <= 0 || argv == NULL || argv[0] == NULL)
		return -1;
	if (t->os != NULL)
		zw_free(t);

	wt = zw_alloc(t);
	if (wt == NULL)
		return -1;

	cmdline = zw_build_cmdline(argc, argv);
	if (cmdline == NULL) {
		zw_free(t);
		return -1;
	}

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	memset(&pi, 0, sizeof(pi));

	ok = CreateProcessA(argv[0], cmdline, NULL, NULL, FALSE,
	    DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi);
	if (!ok) {
		/*
		 * Fallback: let the loader resolve argv[0] from the
		 * command line.  Useful for bare names on PATH.
		 */
		ok = CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
		    DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi);
	}
	free(cmdline);
	if (!ok) {
		zw_free(t);
		return -1;
	}

	wt->pid = pi.dwProcessId;
	wt->process = pi.hProcess;
	wt->launched = 1;
	/*
	 * The initial thread handle from CreateProcess is NOT the
	 * same as the one delivered by CREATE_PROCESS_DEBUG_EVENT.
	 * The event provides a dedicated handle which we store in
	 * the thread table; close this one.
	 */
	if (pi.hThread != NULL)
		CloseHandle(pi.hThread);

	t->pid = (uint64_t)wt->pid;

	/* Drive the event loop until a user-visible stop. */
	memset(&st, 0, sizeof(st));
	if (ztarget_windows_wait(t, &st) < 0) {
		zw_free(t);
		return -1;
	}
	return 0;
}

/* ---------------- attach ---------------- */

int
ztarget_windows_attach(struct ztarget *t, uint64_t pid)
{
	struct zw_target *wt;
	struct zstop st;

	if (t == NULL)
		return -1;
	if (pid == 0 || pid > (uint64_t)0xFFFFFFFFu)
		return -1;
	if (t->os != NULL)
		zw_free(t);
	wt = zw_alloc(t);
	if (wt == NULL)
		return -1;

	wt->pid = (DWORD)pid;
	if (!DebugActiveProcess(wt->pid)) {
		zw_free(t);
		return -1;
	}
	/*
	 * Try to keep the target alive if zdbg exits unexpectedly.
	 * The call may not exist on very old Windows; treat failure
	 * as non-fatal.
	 */
	(void)DebugSetProcessKillOnExit(FALSE);
	wt->attached = 1;

	t->pid = (uint64_t)wt->pid;

	memset(&st, 0, sizeof(st));
	if (ztarget_windows_wait(t, &st) < 0) {
		/* Debug session already cleaned up by kernel on failure. */
		zw_free(t);
		return -1;
	}
	return 0;
}

/* ---------------- detach ---------------- */

int
ztarget_windows_detach(struct ztarget *t)
{
	struct zw_target *wt = zw_get(t);

	if (wt == NULL)
		return -1;

	/*
	 * Best-effort: clear hardware debug registers on every
	 * known thread before giving up the debug session so the
	 * detached process does not keep firing our DRn slots.
	 * Failures are ignored: a stale/exited thread handle is
	 * not worth aborting detach over.
	 */
	if (!wt->exited) {
		(void)ztarget_windows_set_debugreg_all(t, 7, 0);
		(void)ztarget_windows_set_debugreg_all(t, 0, 0);
		(void)ztarget_windows_set_debugreg_all(t, 1, 0);
		(void)ztarget_windows_set_debugreg_all(t, 2, 0);
		(void)ztarget_windows_set_debugreg_all(t, 3, 0);
		(void)ztarget_windows_set_debugreg_all(t, 6, 0);
	}

	if (wt->have_event) {
		(void)ContinueDebugEvent(wt->last_event.dwProcessId,
		    wt->last_event.dwThreadId, DBG_CONTINUE);
		wt->have_event = 0;
	}
	if (!wt->exited)
		(void)DebugActiveProcessStop(wt->pid);

	t->state = ZTARGET_DETACHED;
	zw_free(t);
	return 0;
}

/* ---------------- kill ---------------- */

int
ztarget_windows_kill(struct ztarget *t)
{
	struct zw_target *wt = zw_get(t);

	if (wt == NULL)
		return -1;
	if (wt->process != NULL)
		(void)TerminateProcess(wt->process, 1);
	if (wt->have_event) {
		(void)ContinueDebugEvent(wt->last_event.dwProcessId,
		    wt->last_event.dwThreadId, DBG_CONTINUE);
		wt->have_event = 0;
	}
	/*
	 * Drain the exit event so the debug session closes cleanly.
	 * Best-effort: give up after a short bounded number of
	 * events rather than blocking the REPL forever.
	 */
	{
		int drained = 0;
		DEBUG_EVENT ev;
		while (drained < 64) {
			memset(&ev, 0, sizeof(ev));
			if (!WaitForDebugEvent(&ev, 2000))
				break;
			(void)ContinueDebugEvent(ev.dwProcessId,
			    ev.dwThreadId, DBG_CONTINUE);
			drained++;
			if (ev.dwDebugEventCode ==
			    EXIT_PROCESS_DEBUG_EVENT)
				break;
		}
	}
	t->state = ZTARGET_EXITED;
	zw_free(t);
	return 0;
}

/* ---------------- continue ---------------- */

int
ztarget_windows_continue(struct ztarget *t)
{
	struct zw_target *wt = zw_get(t);

	if (wt == NULL || wt->exited)
		return -1;
	if (!wt->have_event)
		return -1;
	if (!ContinueDebugEvent(wt->last_event.dwProcessId,
	    wt->last_event.dwThreadId, wt->continue_status))
		return -1;
	wt->have_event = 0;
	t->state = ZTARGET_RUNNING;
	return 0;
}

/* ---------------- single-step ---------------- */

int
ztarget_windows_singlestep(struct ztarget *t)
{
	struct zw_target *wt = zw_get(t);
	HANDLE h;
	CONTEXT ctx;

	if (wt == NULL || wt->exited)
		return -1;
	if (!wt->have_event)
		return -1;

	h = zw_current_handle(wt);
	if (h == NULL)
		return -1;

	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_CONTROL;
	if (!GetThreadContext(h, &ctx))
		return -1;
	ctx.EFlags |= 0x100u;	/* TF */
	if (!SetThreadContext(h, &ctx))
		return -1;

	/*
	 * Remember the thread we expect to single-step on, so the
	 * event loop can distinguish a genuine TF stop from a
	 * hardware debug-register trap that also arrives as
	 * EXCEPTION_SINGLE_STEP.
	 */
	wt->singlestep_tid = wt->current_tid;

	if (!ContinueDebugEvent(wt->last_event.dwProcessId,
	    wt->last_event.dwThreadId, wt->continue_status))
		return -1;
	wt->have_event = 0;
	t->state = ZTARGET_RUNNING;
	return 0;
}

/* ---------------- memory ---------------- */

int
ztarget_windows_read(struct ztarget *t, zaddr_t addr, void *buf, size_t len)
{
	struct zw_target *wt = zw_get(t);
	SIZE_T got = 0;

	if (wt == NULL || wt->process == NULL)
		return -1;
	if (len == 0)
		return 0;
	if (buf == NULL)
		return -1;
	if (!ReadProcessMemory(wt->process, (LPCVOID)(uintptr_t)addr,
	    buf, (SIZE_T)len, &got))
		return -1;
	if (got != (SIZE_T)len)
		return -1;
	return 0;
}

int
ztarget_windows_write(struct ztarget *t, zaddr_t addr, const void *buf,
    size_t len)
{
	struct zw_target *wt = zw_get(t);
	SIZE_T done = 0;

	if (wt == NULL || wt->process == NULL)
		return -1;
	if (len == 0)
		return 0;
	if (buf == NULL)
		return -1;
	if (!WriteProcessMemory(wt->process, (LPVOID)(uintptr_t)addr,
	    buf, (SIZE_T)len, &done))
		return -1;
	if (done != (SIZE_T)len)
		return -1;
	return 0;
}

int
ztarget_windows_flush_icache(struct ztarget *t, zaddr_t addr, size_t len)
{
	struct zw_target *wt = zw_get(t);

	if (wt == NULL || wt->process == NULL)
		return -1;
	if (len == 0)
		return 0;
	if (!FlushInstructionCache(wt->process,
	    (LPCVOID)(uintptr_t)addr, (SIZE_T)len))
		return -1;
	return 0;
}

/* ---------------- registers ---------------- */

int
ztarget_windows_getregs(struct ztarget *t, struct zregs *r)
{
	struct zw_target *wt = zw_get(t);
	HANDLE h;
	CONTEXT ctx;

	if (wt == NULL || r == NULL)
		return -1;
#if !defined(_M_X64) && !defined(_M_AMD64) && !defined(__x86_64__)
	return -1;
#else
	h = zw_current_handle(wt);
	if (h == NULL)
		return -1;
	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
	if (!GetThreadContext(h, &ctx))
		return -1;
	r->rax = ctx.Rax;
	r->rbx = ctx.Rbx;
	r->rcx = ctx.Rcx;
	r->rdx = ctx.Rdx;
	r->rsi = ctx.Rsi;
	r->rdi = ctx.Rdi;
	r->rbp = ctx.Rbp;
	r->rsp = ctx.Rsp;
	r->r8  = ctx.R8;
	r->r9  = ctx.R9;
	r->r10 = ctx.R10;
	r->r11 = ctx.R11;
	r->r12 = ctx.R12;
	r->r13 = ctx.R13;
	r->r14 = ctx.R14;
	r->r15 = ctx.R15;
	r->rip = ctx.Rip;
	r->rflags = (uint64_t)ctx.EFlags;
	return 0;
#endif
}

int
ztarget_windows_setregs(struct ztarget *t, const struct zregs *r)
{
	struct zw_target *wt = zw_get(t);
	HANDLE h;
	CONTEXT ctx;

	if (wt == NULL || r == NULL)
		return -1;
#if !defined(_M_X64) && !defined(_M_AMD64) && !defined(__x86_64__)
	return -1;
#else
	h = zw_current_handle(wt);
	if (h == NULL)
		return -1;
	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
	/* Read first so we preserve segment/fp/xmm state we do not touch. */
	if (!GetThreadContext(h, &ctx))
		return -1;
	ctx.Rax = r->rax;
	ctx.Rbx = r->rbx;
	ctx.Rcx = r->rcx;
	ctx.Rdx = r->rdx;
	ctx.Rsi = r->rsi;
	ctx.Rdi = r->rdi;
	ctx.Rbp = r->rbp;
	ctx.Rsp = r->rsp;
	ctx.R8  = r->r8;
	ctx.R9  = r->r9;
	ctx.R10 = r->r10;
	ctx.R11 = r->r11;
	ctx.R12 = r->r12;
	ctx.R13 = r->r13;
	ctx.R14 = r->r14;
	ctx.R15 = r->r15;
	ctx.Rip = r->rip;
	ctx.EFlags = (DWORD)r->rflags;
	if (!SetThreadContext(h, &ctx))
		return -1;
	return 0;
#endif
}

/* ---------------- debug registers ---------------- */

/*
 * Read/write one of the x86-64 debug registers DR0..DR3, DR6,
 * DR7 via CONTEXT_DEBUG_REGISTERS.  DR4 and DR5 are reserved
 * aliases on modern CPUs and are rejected along with any other
 * regno.  On non-x64 Windows builds these return -1 because
 * there is no stable mapping from the generic DR numbering to
 * the platform CONTEXT.
 */

#if defined(_M_X64) || defined(_M_AMD64) || defined(__x86_64__)

static int
zw_ctx_get_dr(const CONTEXT *ctx, int regno, uint64_t *vp)
{
	switch (regno) {
	case 0: *vp = (uint64_t)ctx->Dr0; return 0;
	case 1: *vp = (uint64_t)ctx->Dr1; return 0;
	case 2: *vp = (uint64_t)ctx->Dr2; return 0;
	case 3: *vp = (uint64_t)ctx->Dr3; return 0;
	case 6: *vp = (uint64_t)ctx->Dr6; return 0;
	case 7: *vp = (uint64_t)ctx->Dr7; return 0;
	default: return -1;
	}
}

static int
zw_ctx_set_dr(CONTEXT *ctx, int regno, uint64_t v)
{
	switch (regno) {
	case 0: ctx->Dr0 = (DWORD64)v; return 0;
	case 1: ctx->Dr1 = (DWORD64)v; return 0;
	case 2: ctx->Dr2 = (DWORD64)v; return 0;
	case 3: ctx->Dr3 = (DWORD64)v; return 0;
	case 6: ctx->Dr6 = (DWORD64)v; return 0;
	case 7: ctx->Dr7 = (DWORD64)v; return 0;
	default: return -1;
	}
}

static int
zw_thread_get_debugreg(HANDLE h, int regno, uint64_t *vp)
{
	CONTEXT ctx;

	if (h == NULL)
		return -1;
	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (!GetThreadContext(h, &ctx))
		return -1;
	return zw_ctx_get_dr(&ctx, regno, vp);
}

static int
zw_thread_set_debugreg(HANDLE h, int regno, uint64_t v)
{
	CONTEXT ctx;

	if (h == NULL)
		return -1;
	memset(&ctx, 0, sizeof(ctx));
	/*
	 * Read-modify-write: Win32 does not let us touch a single
	 * DR field in isolation, and the DR fields we do not
	 * intend to change must be preserved.
	 */
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (!GetThreadContext(h, &ctx))
		return -1;
	if (zw_ctx_set_dr(&ctx, regno, v) < 0)
		return -1;
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (!SetThreadContext(h, &ctx))
		return -1;
	return 0;
}

int
ztarget_windows_get_debugreg(struct ztarget *t, int regno, uint64_t *vp)
{
	struct zw_target *wt = zw_get(t);
	HANDLE h;

	if (wt == NULL || vp == NULL)
		return -1;
	if (regno != 0 && regno != 1 && regno != 2 && regno != 3 &&
	    regno != 6 && regno != 7)
		return -1;
	h = zw_current_handle(wt);
	if (h == NULL)
		return -1;
	return zw_thread_get_debugreg(h, regno, vp);
}

int
ztarget_windows_set_debugreg(struct ztarget *t, int regno, uint64_t v)
{
	struct zw_target *wt = zw_get(t);
	HANDLE h;

	if (wt == NULL)
		return -1;
	if (regno != 0 && regno != 1 && regno != 2 && regno != 3 &&
	    regno != 6 && regno != 7)
		return -1;
	h = zw_current_handle(wt);
	if (h == NULL)
		return -1;
	return zw_thread_set_debugreg(h, regno, v);
}

int
ztarget_windows_set_debugreg_all(struct ztarget *t, int regno, uint64_t v)
{
	struct zw_target *wt = zw_get(t);
	int i;
	int ok = 0;

	if (wt == NULL)
		return -1;
	if (regno != 0 && regno != 1 && regno != 2 && regno != 3 &&
	    regno != 6 && regno != 7)
		return -1;
	for (i = 0; i < wt->nthreads; i++) {
		struct zw_thread *th = &wt->threads[i];
		if (th->tid == 0 || th->handle == NULL ||
		    th->state == ZTHREAD_EXITED)
			continue;
		if (zw_thread_set_debugreg(th->handle, regno, v) == 0)
			ok++;
	}
	return ok > 0 ? 0 : -1;
}

#else /* !x86_64 Windows */

int
ztarget_windows_get_debugreg(struct ztarget *t, int regno, uint64_t *vp)
{
	(void)t; (void)regno; (void)vp;
	return -1;
}

int
ztarget_windows_set_debugreg(struct ztarget *t, int regno, uint64_t v)
{
	(void)t; (void)regno; (void)v;
	return -1;
}

int
ztarget_windows_set_debugreg_all(struct ztarget *t, int regno, uint64_t v)
{
	(void)t; (void)regno; (void)v;
	return -1;
}

#endif /* x86_64 Windows */

/* ---------------- threads ---------------- */

int
ztarget_windows_thread_count(struct ztarget *t)
{
	struct zw_target *wt = zw_get(t);
	int n = 0;
	int i;

	if (wt == NULL)
		return 0;
	for (i = 0; i < wt->nthreads; i++) {
		if (wt->threads[i].tid != 0 &&
		    wt->threads[i].state != ZTHREAD_EXITED)
			n++;
	}
	return n;
}

int
ztarget_windows_thread_get(struct ztarget *t, int idx, struct zthread *out)
{
	struct zw_target *wt = zw_get(t);
	int n = 0;
	int i;

	if (wt == NULL || out == NULL || idx < 0)
		return -1;
	for (i = 0; i < wt->nthreads; i++) {
		struct zw_thread *th = &wt->threads[i];
		if (th->tid == 0 || th->state == ZTHREAD_EXITED)
			continue;
		if (n == idx) {
			out->tid = (uint64_t)th->tid;
			out->state = th->state;
			out->last_signal = 0;
			return 0;
		}
		n++;
	}
	return -1;
}

int
ztarget_windows_select_thread(struct ztarget *t, uint64_t tid)
{
	struct zw_target *wt = zw_get(t);
	struct zw_thread *th;

	if (wt == NULL)
		return -1;
	if (tid == 0 || tid > (uint64_t)0xFFFFFFFFu)
		return -1;
	th = zw_find(wt, (DWORD)tid);
	if (th == NULL || th->state == ZTHREAD_EXITED)
		return -1;
	wt->current_tid = th->tid;
	t->tid = (uint64_t)th->tid;
	return 0;
}

uint64_t
ztarget_windows_current_thread(struct ztarget *t)
{
	struct zw_target *wt = zw_get(t);
	if (wt == NULL)
		return 0;
	return (uint64_t)wt->current_tid;
}

int
ztarget_windows_refresh_threads(struct ztarget *t)
{
	/*
	 * Thread table is kept up-to-date by the debug event loop
	 * (CREATE_THREAD_DEBUG_EVENT / EXIT_THREAD_DEBUG_EVENT).
	 * Nothing else to refresh right now.
	 */
	(void)t;
	return 0;
}

/* ---------------- pending signal (not applicable) ---------------- */

int
ztarget_windows_get_pending_signal(struct ztarget *t, uint64_t tid, int *sigp)
{
	(void)t; (void)tid; (void)sigp;
	return -1;
}

int
ztarget_windows_set_pending_signal(struct ztarget *t, uint64_t tid, int sig)
{
	(void)t; (void)tid; (void)sig;
	return -1;
}

/* ---------------- pending exception ---------------- */

/*
 * Check whether wt currently has a real pending EXCEPTION_DEBUG_EVENT.
 * Breakpoint / single-step exceptions are considered debugger-
 * internal and not exposed through the pending-exception API:
 * they are mapped to ZSTOP_BREAKPOINT/ZSTOP_SINGLESTEP above and
 * would not be something the user can meaningfully pass/nopass.
 * Returns 1 if a real exception is pending, 0 otherwise.
 */
static int
zw_pending_real_exception(const struct zw_target *wt, DWORD *codep,
    int *first_chancep)
{
	DWORD code;

	if (wt == NULL || !wt->have_event)
		return 0;
	if (wt->last_event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT)
		return 0;
	code = wt->last_event.u.Exception.ExceptionRecord.ExceptionCode;
	if (code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP)
		return 0;
	if (codep != NULL)
		*codep = code;
	if (first_chancep != NULL)
		*first_chancep =
		    wt->last_event.u.Exception.dwFirstChance ? 1 : 0;
	return 1;
}

int
ztarget_windows_get_pending_exception(struct ztarget *t, uint64_t tid,
    uint32_t *codep, int *first_chancep, int *passp)
{
	struct zw_target *wt = zw_get(t);
	DWORD code = 0;
	int fc = 0;

	(void)tid;	/* Windows debug API has one pending event */
	if (wt == NULL)
		return -1;
	if (!zw_pending_real_exception(wt, &code, &fc))
		return -1;
	if (codep != NULL)
		*codep = (uint32_t)code;
	if (first_chancep != NULL)
		*first_chancep = fc;
	if (passp != NULL)
		*passp = (wt->continue_status == DBG_EXCEPTION_NOT_HANDLED)
		    ? 1 : 0;
	return 0;
}

int
ztarget_windows_set_pending_exception(struct ztarget *t, uint64_t tid,
    uint32_t code, int first_chance, int pass)
{
	struct zw_target *wt = zw_get(t);
	DWORD cur_code = 0;
	int cur_fc = 0;

	(void)tid;
	if (wt == NULL)
		return -1;
	if (!zw_pending_real_exception(wt, &cur_code, &cur_fc))
		return -1;
	/*
	 * The issue explicitly disallows inventing a queue of
	 * exceptions.  If the caller supplies a non-zero code it
	 * must match the pending event.  code==0 means "ignore
	 * code, just apply pass/nopass".
	 */
	if (code != 0 && code != (uint32_t)cur_code)
		return -1;
	if (first_chance >= 0 && first_chance != cur_fc)
		return -1;
	wt->continue_status = pass ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
	return 0;
}

int
ztarget_windows_clear_pending_exception(struct ztarget *t, uint64_t tid)
{
	struct zw_target *wt = zw_get(t);

	(void)tid;
	if (wt == NULL)
		return -1;
	if (!zw_pending_real_exception(wt, NULL, NULL))
		return -1;
	wt->continue_status = DBG_CONTINUE;
	return 0;
}

#endif /* _WIN32 */
