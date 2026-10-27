// Snapshot-only proxy MyDoc.dll: installs NO hooks. When "snap.go" appears in the game folder it
//  1. runs the game's own recruit advisor for a grid of (executor, target) officer pairs -> snap_truth.txt
//  2. dumps all committed non-system memory (exe image, game DLLs, private heaps) -> snap.bin
// Used once to feed the offline test host (host.c).
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <setjmp.h>

#define OFF_BASE 0x1268f20
#define OFF_SIZE 296
#define OFF_N    1700
typedef void (__attribute__((thiscall)) *ctor_t)(void *, int, DWORD, DWORD);
typedef int  (__attribute__((thiscall)) *adv_t)(void *, int);
typedef void (__attribute__((thiscall)) *dtor_t)(void *);

static volatile int probing; static jmp_buf pj;
static void probe_bail(void) { longjmp(pj, 1); }
static LONG CALLBACK probe_veh(EXCEPTION_POINTERS *e) {
    if (probing && e->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) { probing = 0; e->ContextRecord->Eip = (DWORD)probe_bail; return EXCEPTION_CONTINUE_EXECUTION; }
    return EXCEPTION_CONTINUE_SEARCH;
}
static int verdict(DWORD exec, DWORD tgt) {
    static __attribute__((aligned(16))) BYTE ctx[0x400];
    if (setjmp(pj)) return -1;
    probing = 1;
    ((ctor_t)0x49b540)(ctx, 0, exec, tgt);
    int q = ((adv_t)0x49bac0)(ctx, 0);
    ((dtor_t)0x49b570)(ctx);
    probing = 0;
    return q;
}

typedef struct { DWORD ab, base, size, prot; } Reg;
static Reg regs[8192]; static int nr;
typedef struct { DWORD ab, total; } Alloc;
static Alloc als[4096]; static int na;

static int is_system(DWORD addr) {
    char p[MAX_PATH]; char w[MAX_PATH];
    if (!GetMappedFileNameA(GetCurrentProcess(), (void *)addr, p, sizeof p)) return 0;
    GetWindowsDirectoryA(w, sizeof w);
    // mapped names look like \Device\HarddiskVolumeN\Windows\System32\x.dll; match "\Windows\"
    return strstr(p, "\\Windows\\") != NULL || strstr(p, "\\windows\\") != NULL;
}


// record the recruit dialog object (esi at the target-picker call 0x4f5ad0) so the offline tests can find it
volatile DWORD snap_dlg;
__asm__(".globl _snap_stub\n_snap_stub:\n movl %esi,_snap_dlg\n movl $0x57da10,%eax\n jmp *%eax\n");
extern void snap_stub(void);
static void hook_dlg(void) {
    BYTE *p = (BYTE *)0x4f5ad0; DWORD o;
    if (p[0] != 0xe8 || (DWORD)p + 5 + *(int *)(p + 1) != 0x57da10) return;
    VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &o); *(int *)(p + 1) = (DWORD)snap_stub - ((DWORD)p + 5); VirtualProtect(p, 5, o, &o);
}
static void do_snap(void) {
    { FILE *df = fopen("snap_dlg.txt", "w"); fprintf(df, "%lx", snap_dlg); fclose(df); }
    { FILE *tf = fopen("snap_tid.txt", "w"); fprintf(tf, "%lu\n", GetCurrentThreadId()); fclose(tf); }
    FILE *tr = fopen("snap_truth.txt", "w");
    int vs[OFF_N], nv = 0;
    for (int i = 0; i < OFF_N; i++) if (*(DWORD *)(OFF_BASE + i * OFF_SIZE) == 0x616120) vs[nv++] = i;
    int pairs = 0;
    for (int a = 0; a < nv && a < 12; a++) for (int b = 0; b < nv && b < 300; b++) {
        int q = verdict(OFF_BASE + vs[a] * OFF_SIZE, OFF_BASE + vs[b] * OFF_SIZE);
        fprintf(tr, "%d %d %d\n", vs[a], vs[b], q); pairs++;
    }
    fclose(tr);

    MEMORY_BASIC_INFORMATION m; BYTE *a = (BYTE *)0x10000; DWORD total = 0;
    while (a < (BYTE *)0x7ff00000 && VirtualQuery(a, &m, sizeof m)) {
        BYTE *base = m.BaseAddress; SIZE_T sz = m.RegionSize;
        int keep = 0;
        if (m.State == MEM_COMMIT && !(m.Protect & (PAGE_GUARD | PAGE_NOACCESS)) && m.Protect != 0) {
            if (m.Type == MEM_PRIVATE) keep = 1;
            else if (m.Type == MEM_IMAGE && !is_system((DWORD)base)) keep = 1;
        }
        if (m.State != MEM_FREE && m.AllocationBase) {   // reserve extent bookkeeping (any state)
            int i; for (i = 0; i < na; i++) if (als[i].ab == (DWORD)m.AllocationBase) break;
            if (i == na && na < 4096) { als[na].ab = (DWORD)m.AllocationBase; als[na].total = 0; na++; }
            if (i < 4096) als[i].total = (DWORD)(base + sz) - als[i].ab;
        }
        if (keep && nr < 8192) { regs[nr].ab = (DWORD)m.AllocationBase; regs[nr].base = (DWORD)base; regs[nr].size = sz; regs[nr].prot = m.Protect; nr++; total += sz; }
        a = base + sz;
    }
    FILE *o = fopen("snap.bin", "wb");
    fwrite(&nr, 4, 1, o); fwrite(&na, 4, 1, o);
    fwrite(als, sizeof(Alloc), na, o);
    fwrite(regs, sizeof(Reg), nr, o);
    for (int i = 0; i < nr; i++) fwrite((void *)regs[i].base, 1, regs[i].size, o);
    fclose(o);
    FILE *lg = fopen("snap_log.txt", "w"); fprintf(lg, "pairs=%d regions=%d allocs=%d bytes=%lu\n", pairs, nr, na, total); fclose(lg);
}

#define WM_SNAP (WM_APP + 77)
static WNDPROC old_wp;
static LRESULT CALLBACK snap_wp(HWND w, UINT m, WPARAM wp, LPARAM lp) {
    if (m == WM_SNAP) { do_snap(); return 0; }   // runs on the game's UI thread (the advisor needs its thread state)
    return CallWindowProcA(old_wp, w, m, wp, lp);
}
static DWORD WINAPI init(LPVOID p) {
    HWND w = 0; for (int i = 0; i < 600 && !(w = FindWindowA("KOEI_SAN9WINDOW", NULL)); i++) Sleep(100);
    AddVectoredExceptionHandler(1, probe_veh);
    Sleep(2500); hook_dlg();   // wait for the DRM stub to finish decrypting .text
    old_wp = (WNDPROC)SetWindowLongA(w, GWL_WNDPROC, (LONG)snap_wp);
    for (;;) {
        Sleep(500);
        if (GetFileAttributesA("snap.go") != INVALID_FILE_ATTRIBUTES) { DeleteFileA("snap.go"); DWORD_PTR r; SendMessageTimeoutA(w, WM_SNAP, 0, 0, SMTO_NORMAL, 120000, &r); }
    }
    return 0;
}
BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(h); CreateThread(NULL, 0, init, NULL, 0, NULL); }
    return TRUE;
}
