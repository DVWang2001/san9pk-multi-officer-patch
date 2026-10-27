// Test host as a proxy "MyDoc.dll": the (unmodified-on-disk) San9WPK.exe imports it, so the loader runs this DllMain
// right after mapping the exe at 0x400000 and BEFORE the Steam stub / game code runs. We overwrite the exe's
// memory with a snapshot taken from a live game (snap.bin), call the game's advisor functions directly and
// compare with the verdicts recorded in-game (snap_truth.txt). Then we ExitProcess: the game never starts.
#define HOST_TEST
#include "../src/patch.c"
typedef struct { DWORD ab, base, size, prot; } Reg;
typedef struct { DWORD ab, total; } Alloc;
#define IMG_LO 0x400000
#define IMG_HI 0x1bc0000
static FILE *out;
// ---- allocator replacement: heap handles cloned from another process are unusable, so the exe's Heap* imports go to a bump arena (free = no-op)
static BYTE *arena, *arena_top; 
static LPVOID WINAPI h_alloc(HANDLE h, DWORD fl, SIZE_T n) { SIZE_T t = (n + 15) & ~15; BYTE *p = arena_top; arena_top += t + 16; *(DWORD *)p = (DWORD)n; return p + 16; }
static BOOL WINAPI h_free(HANDLE h, DWORD fl, LPVOID p) { return TRUE; }
static SIZE_T WINAPI h_size(HANDLE h, DWORD fl, LPCVOID p) { return ((BYTE *)p >= arena && (BYTE *)p < arena_top) ? *(DWORD *)((BYTE *)p - 16) : 0x1000; }
static LPVOID WINAPI h_realloc(HANDLE h, DWORD fl, LPVOID p, SIZE_T n) {
    LPVOID q = h_alloc(h, fl, n); if (!p) return q;
    SIZE_T old = h_size(h, fl, p); memcpy(q, p, old < n ? old : n); return q;
}
static HANDLE WINAPI h_create(DWORD a, SIZE_T b, SIZE_T c) { return (HANDLE)0x12340000; }
static BOOL WINAPI h_destroy(HANDLE h) { return TRUE; }
static void patch_iat(DWORD slot, void *fn) { DWORD o; VirtualProtect((void *)slot, 4, PAGE_READWRITE, &o); *(DWORD *)slot = (DWORD)fn; }
static DWORD fake_tid; static DWORD WINAPI fake_GetCurrentThreadId(void) { return fake_tid; }
static int already_image(DWORD a) { MEMORY_BASIC_INFORMATION m; return VirtualQuery((void *)a, &m, sizeof m) && m.State != MEM_FREE && m.Type == MEM_IMAGE; }
static int region_ok(DWORD b, DWORD s, DWORD ab) {   // every page of [b,b+s) is free, or reserved-uncommitted inside our own reservation `ab`
    MEMORY_BASIC_INFORMATION m;
    for (DWORD a = b; a < b + s; a = (DWORD)m.BaseAddress + m.RegionSize) {
        if (!VirtualQuery((void *)a, &m, sizeof m)) return 0;
        if (m.State == MEM_FREE) continue;
        if (m.State == MEM_RESERVE && (DWORD)m.AllocationBase == ab) continue;
        return 0;
    }
    return 1;
}
#include "tests_body.inc"
#include "tests_crash.inc"
static void run(void) {
    FILE *f = fopen("snap.bin", "rb"); if (!f) { fprintf(out, "no snap.bin\n"); return; }
    int nr, na; fread(&nr, 4, 1, f); fread(&na, 4, 1, f);
    Alloc *als = malloc(sizeof(Alloc) * na); Reg *regs = malloc(sizeof(Reg) * nr);
    fread(als, sizeof(Alloc), na, f); fread(regs, sizeof(Reg), nr, f);
    // keep the live IAT of the exe (its DLL imports were just resolved by this process's loader)
    IMAGE_DOS_HEADER *dh = (void *)IMG_LO; IMAGE_NT_HEADERS *nt = (void *)(IMG_LO + dh->e_lfanew);
    IMAGE_DATA_DIRECTORY iat = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    DWORD iat_lo = IMG_LO + iat.VirtualAddress, iat_hi = iat_lo + iat.Size;
    BYTE *live_iat = malloc(iat.Size); memcpy(live_iat, (void *)iat_lo, iat.Size);
    int img = 0, other = 0, skipped = 0; DWORD skipped_bytes = 0;
    for (int i = 0; i < na; i++) if (als[i].ab >= IMG_HI && !already_image(als[i].ab)) VirtualAlloc((void *)als[i].ab, als[i].total, MEM_RESERVE, PAGE_EXECUTE_READWRITE);   // reserve whole extents first (heaps grow inside them)
    for (int i = 0; i < nr; i++) {
        BYTE *buf = malloc(regs[i].size); fread(buf, 1, regs[i].size, f);
        DWORD b = regs[i].base, s = regs[i].size, o;
        if (b >= IMG_LO && b + s <= IMG_HI) {                       // exe image: overwrite in place
            VirtualProtect((void *)b, s, PAGE_EXECUTE_READWRITE, &o); memcpy((void *)b, buf, s); img++;
        } else if (!already_image(b)) {                              // game heaps etc. (anything not an image already loaded here)
            if (region_ok(b, s, regs[i].ab) && (VirtualAlloc((void *)b, s, MEM_COMMIT, PAGE_EXECUTE_READWRITE) || VirtualAlloc((void *)b, s, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))) { memcpy((void *)b, buf, s); other++; }
            else { skipped++; skipped_bytes += s; if (skipped <= 12) fprintf(out, "skip base=%lx size=%lx\n", b, s); }
        } else { skipped++; skipped_bytes += s; }
        free(buf);
    }
    fclose(f);
    VirtualProtect((void *)iat_lo, iat.Size, PAGE_EXECUTE_READWRITE, (DWORD[]){0}); memcpy((void *)iat_lo, live_iat, iat.Size);
    fprintf(out, "image regions %d, other mapped %d, skipped %d (%lu bytes)\n", img, other, skipped, skipped_bytes);
    if (IsBadReadPtr((void *)OFF_BASE, 16)) { fprintf(out, "officer array missing\n"); return; }
    { FILE *tf = fopen("snap_tid.txt", "r"); if (tf) { fscanf(tf, "%lu", &fake_tid); fclose(tf); }   // MFC thread-state lookup is keyed by GetCurrentThreadId: pose as the game's UI thread
      DWORD *slot = (DWORD *)0x60f234, o2; VirtualProtect(slot, 4, PAGE_READWRITE, &o2); *slot = (DWORD)fake_GetCurrentThreadId; }
    arena = VirtualAlloc(NULL, 256u << 20, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); arena_top = arena;
    patch_iat(0x60f168, h_alloc); patch_iat(0x60f160, h_free); patch_iat(0x60f164, h_size); patch_iat(0x60f0ec, h_realloc); patch_iat(0x60f15c, h_create); patch_iat(0x60f16c, h_destroy);
    AddVectoredExceptionHandler(1, probe_veh); AddVectoredExceptionHandler(0, crash_log);
    tramp2_p = (BYTE *)0x49bac0;                      // no hook installed here: call the game advisor directly
    run_tests();
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        out = fopen("host_result.txt", "w"); setvbuf(out, NULL, _IONBF, 0);
        run();
        fclose(out);
        ExitProcess(0);
    }
    return TRUE;
}
