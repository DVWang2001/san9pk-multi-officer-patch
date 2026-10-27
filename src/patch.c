// MyDoc.dll proxy: loads inside San9WPK.exe, forwards GetMyDocumentPath to MyDoc_orig.dll.
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <setjmp.h>

static FILE *lg;
static void patch_header(void);
void LOG(const char *f, ...) {
    if (!lg) return;
    fprintf(lg, "%ld ", (long)time(NULL)); va_list a; va_start(a, f); vfprintf(lg, f, a); va_end(a); fputc('\n', lg); fflush(lg);
}

// .text of the exe is DRM-encrypted on disk; once the game window exists it is decrypted in memory.
static void dump_text(void) {
    FILE *o = fopen("san9patch_text.bin", "wb");
    if (!o) return;
    fwrite((void *)0x401000, 1, 0x20d30a, o);  // ponytail: hardcoded v1.2.0.0 .text range
    fclose(o);
    LOG("text dumped");
}

// ---- PAGE_GUARD watcher on the advisor message pages: logs who reads them ----
#define MAXPG 8
static DWORD pg[MAXPG]; static int npg; static int nlog; static DWORD glo, ghi;
static __thread int rearm;
static void arm(void) { for (int i = 0; i < npg; i++) { DWORD o; VirtualProtect((void *)pg[i], 0x1000, PAGE_READWRITE | PAGE_GUARD, &o); } }
static LONG CALLBACK veh(EXCEPTION_POINTERS *e) {
    DWORD c = e->ExceptionRecord->ExceptionCode;
    if (c == 0x80000001) {
        DWORD a = (DWORD)e->ExceptionRecord->ExceptionInformation[1];
        for (int i = 0; i < npg; i++) if (a >= pg[i] && a < pg[i] + 0x1000) {
            static DWORD seen[4096]; static int nseen; DWORD h = e->ContextRecord->Eip; for (int k = 0; k < 40; k++) if (!IsBadReadPtr((DWORD *)e->ContextRecord->Esp + k, 4)) { DWORD v = ((DWORD *)e->ContextRecord->Esp)[k]; if (v >= 0x401000 && v < 0x60e30a) h = h * 31 + v; }
            int dup = 0; for (int k = 0; k < nseen; k++) if (seen[k] == h) dup = 1; if (!dup && nseen < 4096) seen[nseen++] = h;
            if (!dup && (!ghi || (a >= glo && a < ghi)) && nlog++ < 3000) {
                DWORD *sp = (DWORD *)e->ContextRecord->Esp; char b[600]; int n = 0;
                for (int k = 0; k < 160 && n < 500; k++) if (!IsBadReadPtr(sp + k, 4) && sp[k] >= 0x401000 && sp[k] < 0x60e30a) n += sprintf(b + n, " %lx", sp[k]);
                LOG("guard addr=%lx eip=%lx stack:%s", a, e->ContextRecord->Eip, b);
            }
            e->ContextRecord->EFlags |= 0x100; rearm = 1;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    } else if (c == 0x80000004 && rearm) { rearm = 0; arm(); return EXCEPTION_CONTINUE_EXECUTION; }
    return EXCEPTION_CONTINUE_SEARCH;
}
static BYTE *findpat(const BYTE *pat, int n) {
    MEMORY_BASIC_INFORMATION m; BYTE *a = (BYTE *)0x1000000;
    while (a < (BYTE *)0x7ff00000 && VirtualQuery(a, &m, sizeof m)) {
        BYTE *base = m.BaseAddress; SIZE_T sz = m.RegionSize;
        if (m.State == MEM_COMMIT && !(m.Protect & (PAGE_GUARD | PAGE_NOACCESS)) && m.Protect != 0 && !(pat >= base && pat < base + sz))
            for (BYTE *p = base; (p = memchr(p, pat[0], base + sz - p)) && p + n <= base + sz; p++)
                if (!memcmp(p, pat, n) && !(p >= pat && p < pat + n)) return p;
        a = base + sz;
    }
    return 0;
}
// ---- inline hook on message getter 0x5744d0(id, argc, ...): log (caller, id) pairs ----
static DWORD mseen[2048][2]; static int nm;
void __attribute__((cdecl)) logmsg(DWORD ret, DWORD id, DWORD argc) {
    if (ret >= 0x570000 && ret < 0x580000) return;  // loader loop at startup
    for (int i = 0; i < nm; i++) if (mseen[i][0] == ret && mseen[i][1] == id) return;
    if (nm >= 2048) return;
    mseen[nm][0] = ret; mseen[nm][1] = id; nm++;
    LOG("msg ret=%lx id=%lu(0x%lx) argc=%lu", ret, id & 0x7fffffff, id, argc);
}
extern void detour(void);
static BYTE tramp[16];
__asm__(".globl _detour\n_detour:\n pushal\n movl 32(%esp),%eax\n movl 36(%esp),%ebx\n movl 40(%esp),%ecx\n pushl %ecx\n pushl %ebx\n pushl %eax\n call _logmsg\n addl $12,%esp\n popal\n jmp *_tramp_p\n");
BYTE *tramp_p = tramp;
static void hook_msg(void) {
    BYTE *f = (BYTE *)0x5744d0; static const BYTE exp[] = {0x56,0x8b,0x74,0x24,0x08,0x85,0xf6};
    if (memcmp(f, exp, 7)) { LOG("hook_msg: prologue mismatch"); return; }
    DWORD o; VirtualProtect(tramp, 16, PAGE_EXECUTE_READWRITE, &o);
    memcpy(tramp, exp, 7); tramp[7] = 0xe9; *(DWORD *)(tramp + 8) = 0x5744d7 - (DWORD)(tramp + 12);
    VirtualProtect(f, 8, PAGE_EXECUTE_READWRITE, &o);
    f[0] = 0xe9; *(DWORD *)(f + 1) = (DWORD)detour - (DWORD)(f + 5); f[5] = f[6] = 0x90;
    VirtualProtect(f, 8, o, &o);
    LOG("msg hook installed");
}
// ---- crash guard for probing game functions: access violation -> longjmp back ----
static volatile int probing; static jmp_buf pj;
static void probe_bail(void) { longjmp(pj, 1); }
static LONG CALLBACK probe_veh(EXCEPTION_POINTERS *e) {
    if (probing && e->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) { probing = 0; e->ContextRecord->Eip = (DWORD)probe_bail; return EXCEPTION_CONTINUE_EXECUTION; }
    return EXCEPTION_CONTINUE_SEARCH;
}
// ---- wrapper on recruit advisor 0x49bac0 (thiscall, 1 stack arg = show flag, returns 1 good / 3 bad) ----
static BYTE tramp2[16]; static BYTE *tramp2_p = tramp2;
int __attribute__((cdecl, used)) adv_wrap(DWORD self, DWORD arg) {
    int r; DWORD t = (DWORD)tramp2;
    __asm__ volatile("pushl %3\n call *%2" : "=a"(r) : "c"(self), "r"(t), "r"(arg) : "edx", "memory");
    // ponytail: trampoline pops its own arg (ret 4 semantics preserved by original)
    DWORD tgt = IsBadReadPtr((void *)(self + 0x40), 4) ? 0 : *(DWORD *)(self + 0x40);
    LOG("adv49bac0 this=%lx arg=%lu tgt=%lx ret=%d", self, arg, tgt, r);
    if (nlog++ < 6) { char b[900]; int n = 0; for (int i = 0; i < 0x80 && n < 800; i += 4) n += sprintf(b + n, "%lx ", *(DWORD *)(tgt + i)); LOG("tgt: %s", b); }
    static int probed;
    if (arg && GetFileAttributesA("probe.on") != INVALID_FILE_ATTRIBUTES && !IsBadReadPtr((void *)(self + 0x40), 4)) {   // one-off oracle probe: swap target officer, no message (arg=0)
        probed++; static int res[1700]; memset(res, -1, sizeof res); DWORD save = *(DWORD *)(self + 0x40); int c1 = 0, c3 = 0, cx = 0; char b[3000]; int n = 0;
        for (int i = 0; i < 1700; i++) {
            if (i % 100 == 0) LOG("probe i=%d c1=%d c3=%d cx=%d", i, c1, c3, cx);
            DWORD o = 0x1268f20 + i * 296; if (*(DWORD *)o != 0x616120) continue;
            *(DWORD *)(self + 0x40) = o; volatile int q = -1;
            if (setjmp(pj)) { cx++; continue; }
            probing = 1;
            __asm__ volatile("pushl $0\n call *%2" : "=a"(q) : "c"(self), "r"(t) : "edx", "memory");
            probing = 0; res[i] = q;
            if (q == 1) c1++; else if (q == 3) c3++; else cx++;
            if (i < 60) n += sprintf(b + n, "%d:%d ", i, q);
        }
        *(DWORD *)(self + 0x40) = save;
        LOG("probe good=%d bad=%d other=%d  %s", c1, c3, cx, b);
        char fn[32]; sprintf(fn, "probe_%d.txt", probed); FILE *pf = fopen(fn, "w"); if (pf) { for (int i = 0; i < 1700; i++) fprintf(pf, "%d %d\n", i, res[i]); fclose(pf); }
    }
    return r;
}
__asm__(".globl _adv_detour\n_adv_detour:\n pushl 4(%esp)\n pushl %ecx\n call _adv_wrap\n addl $8,%esp\n ret $4\n");
extern void adv_detour(void);
static void hook_adv(void) {
    BYTE *f = (BYTE *)0x49bac0; static const BYTE exp[] = {0x83,0xec,0x10,0x53,0x55};
    if (memcmp(f, exp, 5)) { LOG("hook_adv: prologue mismatch"); return; }
    DWORD o; VirtualProtect(tramp2, 16, PAGE_EXECUTE_READWRITE, &o);
    memcpy(tramp2, exp, 5); tramp2[5] = 0xe9; *(DWORD *)(tramp2 + 6) = 0x49bac5 - (DWORD)(tramp2 + 10);
    VirtualProtect(f, 5, PAGE_EXECUTE_READWRITE, &o);
    f[0] = 0xe9; *(DWORD *)(f + 1) = (DWORD)adv_detour - (DWORD)(f + 5);
    VirtualProtect(f, 5, o, &o);
    AddVectoredExceptionHandler(1, probe_veh);
    LOG("adv hook installed");
}

// ================= feature: mark advisor-approved officers in the 登庸 pickers =================
#define OFF_BASE 0x1268f20
#define OFF_SIZE 296
#define OFF_N    1700
static unsigned char good[OFF_N];      // 1 = advisor says success for this officer in the open picker
static volatile int marking;           // picker open -> name getter appends a marker
typedef void (__attribute__((thiscall)) *ctor_t)(void *, int, DWORD, DWORD);
typedef int  (__attribute__((thiscall)) *adv_t)(void *, int);
typedef void (__attribute__((thiscall)) *dtor_t)(void *);
static int last_q;
static int verdict(DWORD exec, DWORD tgt) {     // 1 good, 0 bad, -1 error; runs the game's own advisor with show=0
    static __attribute__((aligned(16))) BYTE ctx[0x400];
    int r = -1;
    if (setjmp(pj)) return -1;
    probing = 1;
    ((ctor_t)0x49b540)(ctx, 0, exec, tgt);
    int q = ((adv_t)tramp2_p)(ctx, 0);
    ((dtor_t)0x49b570)(ctx);
    probing = 0;
    r = q == 1 ? 1 : q == 3 ? 0 : -1;
    last_q = q;
    return r;
}
static void fill_good(DWORD dlg, int picking_exec) {
    DWORD exec = *(DWORD *)(dlg + 0x12d4), tgt = *(DWORD *)(dlg + 0x12d8); int n = 0;
    memset(good, 0, sizeof good);
    for (int i = 0; i < OFF_N; i++) {
        DWORD o = OFF_BASE + i * OFF_SIZE; if (*(DWORD *)o != 0x616120) continue;
        int v = picking_exec ? (tgt ? verdict(o, tgt) : 0) : (exec ? verdict(exec, o) : 0);
        if (v == 1) { good[i] = 1; n++; }
    }
    LOG("fill_good dlg=%lx exec=%lx tgt=%lx picking_exec=%d good=%d", dlg, exec, tgt, picking_exec, n);
}
// patched call sites of the picker 0x57da10 inside the 登庸 dialog (esi = dialog at both sites)
typedef int (__attribute__((cdecl)) *pick_t)(DWORD, DWORD, DWORD, DWORD, DWORD, DWORD);
static int epick_multi(DWORD dlg, DWORD out, DWORD cand, DWORD msg, DWORD help);
static int lst_items(DWORD l, DWORD *out, int max);
static int mark_targets(DWORD dlg, int ltype, int kind, DWORD cur, DWORD *c, int nc, DWORD *pre, DWORD *pre2, int *np2);
static void sort_front(DWORD cand, DWORD *pre, int npre);
static DWORD rec_tgt;                                         // recruit target chosen in the dialog (for the queued extra executors)
int __attribute__((cdecl, used)) pick_wrap(DWORD dlg, DWORD ret, DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6) {
    int picking_exec = (ret == 0x4f5b53);
    patch_header();
    fill_good(dlg, picking_exec);
    if (picking_exec) return epick_multi(dlg, a1, a2, a3, a4);
    {   // target picker: a target is approved when ANY idle officer of this city would succeed; approved first
        DWORD c[512], pre[512]; int nc = lst_items(a2, c, 512);
        DWORD pre2[512]; int np2;
        int np = mark_targets(dlg, 0x1e, 1, *(DWORD *)(dlg + 0x12d4), c, nc, pre, pre2, &np2);
        sort_front(a2, pre, np); sort_front(a2, pre2, np2);   // order: OK for the current executor, then OK for someone else, then the rest
        LOG("target picker cand=%d approved=%d", nc, np);
    }
    marking = 1;
    if (GetFileAttributesA("trace.on") != INVALID_FILE_ATTRIBUTES) {   // debug: who reads officer 242's name while the picker builds rows
        static int vh; if (!vh) { AddVectoredExceptionHandler(1, veh); vh = 1; }
        glo = OFF_BASE + 242 * OFF_SIZE + 0x10; ghi = glo + 0x10; pg[0] = glo & ~0xfff; npg = 1; arm();
    }
    int r = ((pick_t)0x57da10)(a1, a2, a3, a4, a5, a6);
    if (npg) { DWORD o; npg = 0; VirtualProtect((void *)pg[0], 0x1000, PAGE_READWRITE, &o); }
    marking = 0;
    if (r && !picking_exec) rec_tgt = *(DWORD *)a1;            // target picker: remember the target
    return r;
}
// entry: [esp]=ret, [esp+4..]=6 args; pass esi (dialog) and ret
__asm__(".globl _pick_detour\n_pick_detour:\n"
        " pushl 24(%esp)\n pushl 24(%esp)\n pushl 24(%esp)\n pushl 24(%esp)\n pushl 24(%esp)\n pushl 24(%esp)\n"
        " pushl 24(%esp)\n pushl %esi\n call _pick_wrap\n addl $32,%esp\n ret\n");
extern void pick_detour(void);
static void patch_call_to(DWORD site, DWORD expect, void *to) {
    BYTE *p = (BYTE *)site; DWORD o;
    if (p[0] != 0xe8 || site + 5 + *(int *)(p + 1) != expect) { LOG("patch_call %lx: unexpected bytes", site); return; }
    VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &o);
    *(int *)(p + 1) = (DWORD)to - (site + 5);
    VirtualProtect(p, 5, o, &o);
}
#define patch_call(s, to) patch_call_to(s, 0x57da10, to)
// Officer::GetName(CString *out) at 0x44e600 (thiscall, ret 4) feeds the 武將 column: put ◎ in front when marking
typedef void (__attribute__((thiscall)) *csasg_t)(DWORD, const char *);
static BYTE tramp3[16];
typedef void (__attribute__((thiscall)) *getname_t)(DWORD, DWORD);
typedef void (__attribute__((thiscall)) *cscat_t)(DWORD, const char *);   // CString::operator+=(const char*)
void __attribute__((cdecl, used)) name_wrap(DWORD off, DWORD out, DWORD ret) {
    ((getname_t)tramp3)(off, out);
    int valid = off >= OFF_BASE && off < OFF_BASE + OFF_N * OFF_SIZE && (off - OFF_BASE) % OFF_SIZE == 0;
    if (marking && valid && good[(off - OFF_BASE) / OFF_SIZE]) {   // ◎ (Big5 a1 b7) goes in front of the name
        char b[80]; char *cur = *(char **)out;
        if (cur && strlen(cur) <= 6) { sprintf(b, "\xa1\xb7%s", cur); ((csasg_t)0x5c5fb0)(out, b); }
    }
    if (0 && ret == 0x454b57 && valid) {   // ponytail: list name column is 8 bytes, longer text shows as '*'; 相性 goes to the header instead             // 武將 column of every officer list: show 相性 (officer +0x6c)
        char b[16]; sprintf(b, "(%d)", *(int *)(off + 0x6c));
        ((cscat_t)0x5c6110)(out, b);
    }
}
__asm__(".globl _name_detour\n_name_detour:\n pushl (%esp)\n pushl 8(%esp)\n pushl %ecx\n call _name_wrap\n addl $12,%esp\n ret $4\n");
extern void name_detour(void);

// ================= feature: 相性 in the 武將情報 header (姓名〈字〉 builder 0x44f1f0, 3 call sites) =================
typedef char *(__attribute__((thiscall)) *style_t)(DWORD);
char *__attribute__((cdecl, used)) style_wrap(DWORD off) {
    char *s = ((style_t)0x44f1f0)(off);
    if (s && off >= OFF_BASE && off < OFF_BASE + OFF_N * OFF_SIZE && (off - OFF_BASE) % OFF_SIZE == 0)
        sprintf(s + strlen(s), "\xa1\x40\xac\xdb\xa9\xca%d", *(int *)(off + 0x6c));   // full-width space + 相性 + value
    return s;
}
__asm__(".globl _style_detour\n_style_detour:\n pushl %ecx\n call _style_wrap\n addl $4,%esp\n ret\n");
extern void style_detour(void);

// ================= feature: multi-officer 探索 / 登庸 =================
// The pickers become the game's own multi-select list (0x57db90, as used by 移動), pre-checked with advisor-approved rows.
// The dialog still issues one command; the rest are queued and handed out by the city-menu loop
// (dispatcher 0x517f30 calls CreateCommand again while [menu+0x3c] > 0).
typedef void (__attribute__((thiscall)) *lst_ctor_t)(void *);
typedef void (__attribute__((thiscall)) *lst_add_t)(void *, DWORD);
typedef void (__attribute__((thiscall)) *lst_build_t)(DWORD, int, int);
typedef int  (__attribute__((cdecl))   *mpick_t)(void *, DWORD, int, DWORD, DWORD, int, int);
typedef void *(__attribute__((cdecl))  *new_t)(DWORD);
#define LST_COUNT(l) (*(int *)((BYTE *)(l) + 0xc))
static int verdict_explore(DWORD exec, DWORD rg);
static int lst_items(DWORD l, DWORD *out, int max) {          // node {next, prev, data}; head at +4
    int n = 0; for (DWORD *nd = *(DWORD **)(l + 4); nd && n < max; nd = (DWORD *)nd[0]) out[n++] = nd[2];
    return n;
}
#define QMAX 512
static DWORD q_exec[QMAX], q_tgt[QMAX]; static int q_n, q_i, q_kind;   // kind 1 recruit, 2 explore
static DWORD sel_exec[QMAX]; static int sel_n;                        // explore: officers checked in the multi picker
static DWORD rec_pair_e[QMAX], rec_pair_t[QMAX]; static int rec_n;      // recruit: (executor, target) chosen at pick time
static void patch_header(void);
static void sort_front(DWORD cand, DWORD *pre, int npre) {   // advisor-approved rows first: stable-partition the candidate list's data pointers in place
    DWORD *nd[512]; DWORD d[512], p1[512]; int n = 0, k = 0;
    for (DWORD *x = *(DWORD **)(cand + 4); x && n < 512; x = (DWORD *)x[0]) { nd[n] = x; d[n++] = x[2]; }
    for (int i = 0; i < n; i++) for (int j = 0; j < npre; j++) if (d[i] == pre[j]) { p1[k++] = d[i]; break; }
    for (int i = 0; i < n; i++) { int in = 0; for (int j = 0; j < npre; j++) if (d[i] == pre[j]) in = 1; if (!in) p1[k++] = d[i]; }
    for (int i = 0; i < n; i++) nd[i][2] = p1[i];
}
static int multi_pick(DWORD cand, DWORD *pre, int npre, int maxsel, DWORD msg, DWORD help, DWORD *sel) {
    patch_header();
    static __attribute__((aligned(16))) BYTE outl[0x40];
    ((lst_ctor_t)0x476190)(outl);
    sort_front(cand, pre, npre);
    marking = 1;
    if (GetFileAttributesA("trace.on") != INVALID_FILE_ATTRIBUTES) {   // debug: who reads officer 242's record
        static int vh; if (!vh) { AddVectoredExceptionHandler(1, veh); vh = 1; }
        glo = OFF_BASE + 242 * OFF_SIZE; ghi = glo + OFF_SIZE; pg[0] = glo & ~0xfff; npg = 1; arm();
    }
    int r = ((mpick_t)0x57db90)(outl, cand, maxsel, msg, help, 1, 0);
    if (npg) { DWORD o; npg = 0; VirtualProtect((void *)pg[0], 0x1000, PAGE_READWRITE, &o); }
    marking = 0;
    int n = r ? lst_items((DWORD)outl, sel, QMAX) : 0;
    ((lst_ctor_t)0x4761b0)(outl);
    return n;
}
// explore: executor picker call at 0x4f4ea4 -> 57da10(&dlg[0xed4], cand, 0x1f65, help, 0, 0)
int __attribute__((cdecl, used)) xpick_wrap(DWORD dlg, DWORD ret, DWORD out, DWORD cand, DWORD msg, DWORD help, DWORD a5, DWORD a6) {
    DWORD c[QMAX], pre[QMAX]; int nc = lst_items(cand, c, QMAX), np = 0;
    DWORD rg = *(DWORD *)(dlg + 0xed8);
    memset(good, 0, sizeof good);
    for (int i = 0; i < nc; i++) if (rg && verdict_explore(c[i], rg) == 1) {
        pre[np++] = c[i];
        if (c[i] >= OFF_BASE && c[i] < OFF_BASE + OFF_N * OFF_SIZE) good[(c[i] - OFF_BASE) / OFF_SIZE] = 1;
    }
    int n = multi_pick(cand, pre, np, nc, msg, help, sel_exec);
    LOG("explore multi-pick region=%lx cand=%d pre=%d picked=%d", rg, nc, np, n);
    if (n <= 0) return 0;
    sel_n = n; *(DWORD *)out = sel_exec[0];
    return 1;
}
// recruit: executor picker call at 0x4f5b4e -> multi-select; every picked officer recruits the dialog's target
static int epick_multi(DWORD dlg, DWORD out, DWORD cand, DWORD msg, DWORD help) {
    DWORD c[QMAX], pre[QMAX], sel[QMAX]; int nc = lst_items(cand, c, QMAX), np = 0;
    DWORD tg = *(DWORD *)(dlg + 0x12d8);
    for (int i = 0; i < nc; i++) if (tg && verdict(c[i], tg) == 1) pre[np++] = c[i];
    int n = multi_pick(cand, pre, np, nc, msg, help, sel);
    LOG("recruit executor multi-pick tgt=%lx cand=%d pre=%d picked=%d", tg, nc, np, n);
    if (n <= 0) return 0;
    rec_n = n; if (tg) rec_tgt = tg;
    for (int k = 0; k < n; k++) rec_pair_e[k] = sel[k];
    *(DWORD *)out = sel[0];
    return 1;
}
__asm__(".globl _xpick_detour\n_xpick_detour:\n"
        " pushl 24(%esp)\n pushl 24(%esp)\n pushl 24(%esp)\n pushl 24(%esp)\n pushl 24(%esp)\n pushl 24(%esp)\n"
        " pushl 24(%esp)\n pushl %esi\n call _xpick_wrap\n addl $32,%esp\n ret\n");
extern void xpick_detour(void);
// city-menu CreateCommand slots: recruit 0x4cef10 (vtable 0x61a030+0x28), explore 0x4ce910 (0x619fd0+0x28)
typedef DWORD (__attribute__((thiscall)) *mk_t)(DWORD);
static DWORD next_queued(DWORD self, int kind) {              // build the next queued command without a dialog
    if (q_kind != kind || q_i >= q_n) return 0;
    int i = q_i++;
    void *p = ((new_t)0x5ee280)(kind == 1 ? 0x50 : 0x44);
    if (!p) return 0;
    ((ctor_t)(kind == 1 ? 0x49b540 : 0x49a4a0))(p, self, q_exec[i], q_tgt[i]);
    LOG("queued cmd %d/%d kind=%d exec=%lx tgt=%lx", i + 1, q_n, kind, q_exec[i], q_tgt[i]);
    return (DWORD)p;
}
static void start_queue(DWORD self, int kind) {
    if (q_n > 0) { *(int *)(self + 0x3c) += q_n; q_kind = kind; q_i = 0; LOG("queue %d extra (kind %d), counter=%d", q_n, kind, *(int *)(self + 0x3c)); }
}
DWORD __attribute__((cdecl, used)) mkrec_wrap(DWORD self, DWORD ret) {
    DWORD c = next_queued(self, 1);
    if (c) return c;
    q_n = q_i = 0; rec_n = 0; rec_tgt = 0;
    c = ((mk_t)0x4cef10)(self);
    if (c && rec_n > 1 && rec_tgt) { for (int k = 1; k < rec_n; k++) { q_exec[q_n] = rec_pair_e[k]; q_tgt[q_n] = rec_tgt; q_n++; } start_queue(self, 1); }
    rec_n = 0;
    return c;
}
DWORD __attribute__((cdecl, used)) mkexp_wrap(DWORD self, DWORD ret) {
    DWORD c = next_queued(self, 2);
    if (c) return c;
    q_n = q_i = 0; sel_n = 0;
    c = ((mk_t)0x4ce910)(self);
    if (c && sel_n > 1) {
        DWORD rg = *(DWORD *)(c + 0x40);
        for (int k = 1; k < sel_n; k++) { q_exec[q_n] = sel_exec[k]; q_tgt[q_n] = rg; q_n++; }
        start_queue(self, 2);
    }
    sel_n = 0;
    return c;
}
__asm__(".globl _mkrec_detour\n_mkrec_detour:\n pushl (%esp)\n pushl %ecx\n call _mkrec_wrap\n addl $8,%esp\n ret\n");
__asm__(".globl _mkexp_detour\n_mkexp_detour:\n pushl (%esp)\n pushl %ecx\n call _mkexp_wrap\n addl $8,%esp\n ret\n");
extern void mkrec_detour(void); extern void mkexp_detour(void);
static void set_vslot(DWORD slot, DWORD expect, void *to) {
    DWORD o; if (*(DWORD *)slot != expect) { LOG("vslot %lx unexpected", slot); return; }
    VirtualProtect((void *)slot, 4, PAGE_READWRITE, &o); *(DWORD *)slot = (DWORD)to; VirtualProtect((void *)slot, 4, o, &o);
}

// ---- debug trace: CString::operator=(const char*) callers while a picker is open (trace2.on) ----
static BYTE tramp4[16]; static int trace2;
void __attribute__((cdecl, used)) cs_log(DWORD ret, DWORD cs, const char *s) {
    if (!trace2 || !marking) return;
    static DWORD seen[512]; static int n; DWORD h = ret * 31 + (s ? (BYTE)s[0] * 7 + strlen(s) : 0);
    for (int i = 0; i < n; i++) if (seen[i] == h) return;
    if (n < 512) seen[n++] = h;
    char hx[64]; int k = 0; for (int i = 0; s && i < 14 && s[i]; i++) k += sprintf(hx + k, "%02x", (BYTE)s[i]);
    LOG("cs= ret=%lx len=%d hex=%s", ret, s ? (int)strlen(s) : -1, hx);
}
__asm__(".globl _cs_detour\n_cs_detour:\n pushal\n pushl 40(%esp)\n pushl %ecx\n pushl 40(%esp)\n call _cs_log\n addl $12,%esp\n popal\n jmp *_tramp4_p\n");
BYTE *tramp4_p = tramp4;
extern void cs_detour(void);
static void hook_cs(void) {
    BYTE *f = (BYTE *)0x5c5fb0; static const BYTE exp[] = {0x53,0x55,0x56,0x8b,0x74,0x24,0x10};
    if (memcmp(f, exp, 7)) { LOG("hook_cs mismatch"); return; }
    DWORD o; VirtualProtect(tramp4, 16, PAGE_EXECUTE_READWRITE, &o);
    memcpy(tramp4, exp, 7); tramp4[7] = 0xe9; *(DWORD *)(tramp4 + 8) = 0x5c5fb7 - (DWORD)(tramp4 + 12);
    VirtualProtect(f, 7, PAGE_EXECUTE_READWRITE, &o);
    f[0] = 0xe9; *(DWORD *)(f + 1) = (DWORD)cs_detour - (DWORD)(f + 5); f[5] = f[6] = 0x90;
    VirtualProtect(f, 7, o, &o);
}

// ================= 個人/各 tab cell text: Officer::GetCellText(CString *out, int col) at 0x454940 (thiscall, ret 8) =================
static void patch_header(void);
static BYTE tramp5[24]; static int cellcol = -1;
static int cellcol_ok(void) { return cellcol >= 0; }   // cellcol: column id that displays 相性 (-1 = off)
typedef int (__attribute__((thiscall)) *cell_t)(DWORD, DWORD, DWORD);
int __attribute__((cdecl, used)) cell_wrap(DWORD off, DWORD out, DWORD col) {
    int r = ((cell_t)tramp5)(off, out, col);
    int valid = off >= OFF_BASE && off < OFF_BASE + OFF_N * OFF_SIZE && (off - OFF_BASE) % OFF_SIZE == 0;
    if (!valid) return r;
    if (trace2 && marking) { static int seen[256]; int h = col * 7 + (*(char **)out ? (BYTE)(*(char **)out)[0] : 0); int k; for (k = 0; k < 256 && seen[k] != h + 1; k++) if (!seen[k]) break; if (k < 256 && seen[k] != h + 1) { seen[k] = h + 1; LOG("cell col=%lu text=%s", col, *(char **)out); } }
    if ((int)col == cellcol && marking) { char b[16]; sprintf(b, "%d", *(int *)(off + 0x6c)); ((csasg_t)0x5c5fb0)(out, b); r = strlen(b); }
    return r;
}
__asm__(".globl _cell_detour\n_cell_detour:\n pushl 8(%esp)\n pushl 8(%esp)\n pushl %ecx\n call _cell_wrap\n addl $12,%esp\n ret $8\n");
extern void cell_detour(void);
static void hook_cell(void) {
    BYTE *f = (BYTE *)0x454940; static const BYTE exp[] = {0x83,0xec,0x0c,0x53,0x55};
    if (memcmp(f, exp, 5)) { LOG("hook_cell mismatch"); return; }
    DWORD o; VirtualProtect(tramp5, 24, PAGE_EXECUTE_READWRITE, &o);
    memcpy(tramp5, exp, 5); tramp5[5] = 0xe9; *(DWORD *)(tramp5 + 6) = 0x454945 - (DWORD)(tramp5 + 10);
    VirtualProtect(f, 5, PAGE_EXECUTE_READWRITE, &o);
    f[0] = 0xe9; *(DWORD *)(f + 1) = (DWORD)cell_detour - (DWORD)(f + 5);
    VirtualProtect(f, 5, o, &o);
    LOG("cell hook installed");
}

// rename the 個人-tab header 擢昇 -> 相性 (same 4 Big5 bytes) inside the decompressed message pool
static int hdr_done;
static void patch_header(void) {
    if (GetFileAttributesA("no_hdr.on") != INVALID_FILE_ATTRIBUTES) return;
    static const BYTE pat[] = "\xa8\xec\xb9\x46\xb9\x77\xa9\x77\x05\x05\x05\xc0\xc2\xaa\x40\x05\x05\x05\xbd\x73\xbf\xe8";   // 到達預定 擢昇 編輯, entries separated by 05 05 05
    BYTE *p = findpat(pat, sizeof pat - 1);
    if (!p) return;
    DWORD op; VirtualProtect(p + 11, 4, PAGE_READWRITE, &op);
    memcpy(p + 11, "\xac\xdb\xa9\xca", 4);   // 相性
    cellcol = 185; hdr_done = 1;
    LOG("header patched at %p", p);
}

// ================= generic "scheme" commands (executor multi-pick against a fixed target) =================
// kind 3 奪取, 4 燒夷, 5 流言 : dialog target at [dlg+tgtoff]; advisor ctx ctor(ctx,0,exec,tgt) + advisor fn; command ctor(cmd,menu,exec,tgt)
typedef struct { DWORD tgtoff, ctx_ctor, ctx_dtor, adv, cmd_ctor, cmd_size, tgt2off, tgt2addr; } Sch;
typedef void (__attribute__((thiscall)) *ctor4_t)(void *, int, DWORD, DWORD, DWORD);
static DWORD q_tgt2[QMAX];
static const Sch SCH[10] = {
    {0},{0},{0},
    {0x6f8, 0x4938b0, 0x4938e0, 0x498830, 0x4938b0, 0x44},   /* 3 奪取 */
    {0x6f8, 0x49c880, 0x49c8b0, 0x498830, 0x49c880, 0x44, 0},   /* 4 燒夷 */
    {0x130c, 0x499df0, 0x499e20, 0x498830, 0x499df0, 0x48, 0x1310},   /* 5 流言 */
    {0x140c, 0x4997a0, 0x4997d0, 0x498830, 0x4997a0, 0x44, 0},        /* 6 離間 (target officer picked first, executors paired automatically) */
    {4,     0x497470, 0x4974b0, 0x497990, 0x497470, 0x40, 0, 0},      /* 7 勸降: esi=&exec, force=[esi+4] */
    {0x71c, 0x49d640, 0x49d6a0, 0x49e4e0, 0x49d640, 0x40, 0x720, 0},  /* 8 請求: dlg+0x71c target force/facility, +0x720 */
    {0x159c,0x49f210, 0x49f280, 0x49f740, 0x49f210, 0x40, 0x15a0, 1}, /* 9 贈與: dlg+0x159c force, ptr arg = &dlg[0x15a0] (copied) */
};
static DWORD pk_tg, pk_tg2; static BYTE giftbuf[0x40];
static int verdict_sch(int kind, DWORD exec, DWORD tgt, DWORD tgt2) {
    const Sch *s = &SCH[kind]; static __attribute__((aligned(16))) BYTE ctx[0x400];
    if (setjmp(pj)) return -1;
    probing = 1;
    if (s->tgt2off) ((ctor4_t)s->ctx_ctor)(ctx, 0, exec, tgt, tgt2); else ((ctor_t)s->ctx_ctor)(ctx, 0, exec, tgt);
    int q = ((adv_t)s->adv)(ctx, 0);   // ponytail: adv fn address == vtable slot target
    ((dtor_t)s->ctx_dtor)(ctx);
    probing = 0;
    return q == 1 ? 1 : q == 3 ? 0 : -1;
}
// fills good[]/pre[] for the candidate targets c[]: approved if some idle officer (list type ltype at dlg+0x6b4) gets advisor "good"; kind 1 recruit, 6 離間
static int mark_targets(DWORD dlg, int ltype, int kind, DWORD cur, DWORD *c, int nc, DWORD *pre, DWORD *pre2, int *np2) {
    DWORD ex[512]; int np = 0; *np2 = 0;
    ((lst_build_t)0x4748a0)(dlg + 0x6b4, ltype, 0);
    int ne = lst_items(dlg + 0x6b4, ex, 512);
    memset(good, 0, sizeof good);
    for (int t = 0; t < nc; t++) for (int e = 0; e < ne; e++) if ((kind == 1 ? verdict(ex[e], c[t]) : verdict_sch(kind, ex[e], c[t], 0)) == 1) {
        pre[np++] = c[t];
        if (c[t] >= OFF_BASE && c[t] < OFF_BASE + OFF_N * OFF_SIZE) good[(c[t] - OFF_BASE) / OFF_SIZE] = 1;
        break;
    }
    if (cur) for (int t = 0; t < np; t++) if ((kind == 1 ? verdict(cur, pre[t]) : verdict_sch(kind, cur, pre[t], 0)) == 1) pre2[(*np2)++] = pre[t];
    return np;
}
int __attribute__((cdecl, used)) spick_wrap(int kind, DWORD dlg, DWORD ret, DWORD out, DWORD cand, DWORD msg, DWORD help, DWORD a5, DWORD a6) {
    DWORD c[QMAX], pre[QMAX]; int nc = lst_items(cand, c, QMAX), np = 0;
    DWORD tg = *(DWORD *)(dlg + SCH[kind].tgtoff), tg2 = 0;
    if (SCH[kind].tgt2off) { if (SCH[kind].tgt2addr) { memcpy(giftbuf, (void *)(dlg + SCH[kind].tgt2off), sizeof giftbuf); tg2 = (DWORD)giftbuf; } else tg2 = *(DWORD *)(dlg + SCH[kind].tgt2off); }
    pk_tg = tg; pk_tg2 = tg2;
    memset(good, 0, sizeof good);
    for (int i = 0; i < nc; i++) if (tg && (!SCH[kind].tgt2off || tg2) && verdict_sch(kind, c[i], tg, tg2) == 1) {
        pre[np++] = c[i];
        if (c[i] >= OFF_BASE && c[i] < OFF_BASE + OFF_N * OFF_SIZE) good[(c[i] - OFF_BASE) / OFF_SIZE] = 1;
    }
    int n = multi_pick(cand, pre, np, nc, msg, help, sel_exec);
    LOG("scheme %d multi-pick tgt=%lx cand=%d pre=%d picked=%d", kind, tg, nc, np, n);
    if (n <= 0) return 0;
    sel_n = n; *(DWORD *)out = sel_exec[0];
    return 1;
}
#define SPICK_STUB(K) __asm__(".globl _spick" #K "_detour" "\n" "_spick" #K "_detour:" "\n" \
    " pushl 24(%esp)" "\n" " pushl 24(%esp)" "\n" " pushl 24(%esp)" "\n" " pushl 24(%esp)" "\n" " pushl 24(%esp)" "\n" " pushl 24(%esp)" "\n" \
    " pushl 24(%esp)" "\n" " pushl %esi" "\n" " pushl $" #K "\n" " call _spick_wrap" "\n" " addl $36,%esp" "\n" " ret" "\n"); \
    extern void spick##K##_detour(void);
SPICK_STUB(3)
SPICK_STUB(4)
SPICK_STUB(5)
SPICK_STUB(7)
SPICK_STUB(8)
SPICK_STUB(9)

SPICK_STUB(6)
// 離間 target picker (single): executor at [dlg+0x1408]; approved targets first + ◎
int __attribute__((cdecl, used)) tpick6_wrap(DWORD dlg, DWORD ret, DWORD out, DWORD cand, DWORD msg, DWORD help, DWORD a5, DWORD a6) {
    DWORD c[512], pre[512]; int nc = lst_items(cand, c, 512);
    DWORD pre2[512]; int np2;
    int np = mark_targets(dlg, 0x1d, 6, *(DWORD *)(dlg + 0x1408), c, nc, pre, pre2, &np2);
    patch_header();
    sort_front(cand, pre, np); sort_front(cand, pre2, np2);
    marking = 1;
    int r = ((pick_t)0x57da10)(out, cand, msg, help, a5, a6);
    marking = 0;
    return r;
}
__asm__(".globl _tpick6_detour\n_tpick6_detour:\n"
        " pushl 24(%esp)\n pushl 24(%esp)\n pushl 24(%esp)\n pushl 24(%esp)\n pushl 24(%esp)\n pushl 24(%esp)\n"
        " pushl 24(%esp)\n pushl %esi\n call _tpick6_wrap\n addl $32,%esp\n ret\n");
extern void tpick6_detour(void);

DWORD __attribute__((cdecl, used)) mksch_wrap(int kind, DWORD self, DWORD factory) {
    DWORD c = 0;
    if (q_kind == kind && q_i < q_n) {                        // queued extra command
        int i = q_i++; void *p = ((new_t)0x5ee280)(SCH[kind].cmd_size);
        if (!p) return 0;
        if (SCH[kind].tgt2off) ((ctor4_t)SCH[kind].cmd_ctor)(p, self, q_exec[i], q_tgt[i], q_tgt2[i]); else ((ctor_t)SCH[kind].cmd_ctor)(p, self, q_exec[i], q_tgt[i]);
        LOG("queued cmd %d/%d kind=%d exec=%lx tgt=%lx", i + 1, q_n, kind, q_exec[i], q_tgt[i]);
        return (DWORD)p;
    }
    q_n = q_i = 0; sel_n = 0;
    c = ((mk_t)factory)(self);
    if (c && sel_n > 1) {
        DWORD tg = *(DWORD *)(c + 0x40), tg2 = SCH[kind].tgt2off ? *(DWORD *)(c + 0x44) : 0;
        if (kind >= 7) { tg = pk_tg; tg2 = pk_tg2; }
        for (int k = 1; k < sel_n; k++) { q_exec[q_n] = sel_exec[k]; q_tgt[q_n] = tg; q_tgt2[q_n] = tg2; q_n++; }
        start_queue(self, kind);
    }
    sel_n = 0;
    return c;
}
#define MKSCH_STUB(K, FACT) __asm__(".globl _mksch" #K "_detour" "\n" "_mksch" #K "_detour:" "\n" \
    " pushl $" #FACT "\n" " pushl %ecx" "\n" " pushl $" #K "\n" " call _mksch_wrap" "\n" " addl $12,%esp" "\n" " ret" "\n"); \
    extern void mksch##K##_detour(void);
MKSCH_STUB(3, 0x4c7340)
MKSCH_STUB(4, 0x4cf520)
MKSCH_STUB(5, 0x4cd3f0)
MKSCH_STUB(6, 0x4cd020)
#define MKSCH_STUB2(N, K, FACT) __asm__(".globl _mksch" #N "_detour" "\n" "_mksch" #N "_detour:" "\n" \
    " pushl $" #FACT "\n" " pushl %ecx" "\n" " pushl $" #K "\n" " call _mksch_wrap" "\n" " addl $12,%esp" "\n" " ret" "\n"); \
    extern void mksch##N##_detour(void);
MKSCH_STUB2(7a, 7, 0x4ca2a0)
MKSCH_STUB2(7b, 7, 0x4b3ad0)
MKSCH_STUB2(8a, 8, 0x4cfe50)
MKSCH_STUB2(8b, 8, 0x4c2a80)
MKSCH_STUB2(9a, 9, 0x4d0b20)
MKSCH_STUB2(9b, 9, 0x4c47c0)
extern void rpick_detour(void);
extern void asg_detour(void);
static void hook_recruit_marks(void) {
    BYTE *f = (BYTE *)0x44e600; static const BYTE exp[] = {0x56,0x8b,0xf1,0x57,0x8b,0x7c,0x24,0x0c};
    if (memcmp(f, exp, 8)) { LOG("hook name: prologue mismatch"); return; }
    DWORD o; VirtualProtect(tramp3, 16, PAGE_EXECUTE_READWRITE, &o);
    memcpy(tramp3, exp, 8);                                   // push esi; mov esi,ecx; push edi; mov edi,[esp+0xc]
    tramp3[8] = 0xe9; *(DWORD *)(tramp3 + 9) = 0x44e608 - (DWORD)(tramp3 + 13);
    VirtualProtect(f, 8, PAGE_EXECUTE_READWRITE, &o);
    f[0] = 0xe9; *(DWORD *)(f + 1) = (DWORD)name_detour - (DWORD)(f + 5); f[5] = f[6] = f[7] = 0x90;
    VirtualProtect(f, 8, o, &o);
    patch_call(0x4f5ad0, pick_detour);  // 登庸 target picker -> multi-select
    patch_call(0x4f5b4e, pick_detour);   // 登庸 executor picker (single, ◎ marks)
    patch_call(0x4f4ea4, xpick_detour);  // 探索 executor picker -> multi-select
    patch_call_to(0x4f4e11, 0x4f4980, rpick_detour);   // explore region picker
    patch_call_to(0x43bcbd, 0x5c5fb0, asg_detour);     // region list column text
    patch_call_to(0x59ded2, 0x44f1f0, style_detour);
    patch_call_to(0x5ac910, 0x44f1f0, style_detour);
    patch_call_to(0x5ac93d, 0x44f1f0, style_detour);
    set_vslot(0x61a058, 0x4cef10, mkrec_detour);
    set_vslot(0x619ff8, 0x4ce910, mkexp_detour);
    if (GetFileAttributesA("trace2.on") != INVALID_FILE_ATTRIBUTES) { trace2 = 1; }
    if (GetFileAttributesA("no_cell.on") == INVALID_FILE_ATTRIBUTES) hook_cell();
    patch_call_to(0x4d751b, 0x57da10, spick3_detour);   // 奪取 executor picker -> multi-select
    set_vslot(0x619a70, 0x4c7340, mksch3_detour);       // 奪取 CreateCommand
    patch_call_to(0x4f6a7b, 0x57da10, spick4_detour);   // 燒夷 executor picker -> multi-select
    set_vslot(0x61a0b8, 0x4cf520, mksch4_detour);       // 燒夷 CreateCommand
    patch_call_to(0x4ea44b, 0x57da10, spick5_detour);   // 流言 executor picker -> multi-select
    set_vslot(0x619f08, 0x4cd3f0, mksch5_detour);       // 流言 CreateCommand
    patch_call_to(0x4e96ad, 0x57da10, tpick6_detour);   // 離間 target picker (single, sorted + ◎)
    patch_call_to(0x4e972b, 0x57da10, spick6_detour);   // 離間 executor picker -> multi-select
    set_vslot(0x619ed8, 0x4cd020, mksch6_detour);       // 離間 CreateCommand
    patch_call_to(0x4e464b, 0x57da10, spick7_detour);   // 勸降 executor picker
    set_vslot(0x619ce0, 0x4ca2a0, mksch7a_detour); set_vslot(0x61948c, 0x4b3ad0, mksch7b_detour);
    patch_call_to(0x4f856b, 0x57da10, spick8_detour);   // 請求 executor picker
    set_vslot(0x61a118, 0x4cfe50, mksch8a_detour); set_vslot(0x61985c, 0x4c2a80, mksch8b_detour);
    patch_call_to(0x4fb77b, 0x57da10, spick9_detour);   // 贈與 executor picker
    set_vslot(0x61a178, 0x4d0b20, mksch9a_detour); set_vslot(0x6198e8, 0x4c47c0, mksch9b_detour);
    LOG("recruit marks installed");
}

// ================= feature: mark advisor-approved regions with ◎ in the 探索 region picker =================
// explore dialog: exec [+0xed4], region [+0xed8]; regions: 137 at 0x12480b8 (stride 444) + 50 cities at 0x125db98 (stride 496), name at +0x20
#define RG_BASE 0x12480b8
#define RG_SIZE 444
#define RG_N    137
#define CT_BASE 0x125db98
#define CT_SIZE 496
#define CT_N    50
static unsigned char rgood[RG_N + CT_N];
static volatile int marking_rg;
static DWORD region_at(int i) { return i < RG_N ? RG_BASE + i * RG_SIZE : CT_BASE + (i - RG_N) * CT_SIZE; }
static int verdict_explore(DWORD exec, DWORD rg) {   // 1 good, 0 not, -1 error; game's explore advisor 0x49b160 with show=0
    static __attribute__((aligned(16))) BYTE ctx[0x400];
    if (setjmp(pj)) return -1;
    probing = 1;
    ((ctor_t)0x49a4a0)(ctx, 0, exec, rg);
    int q = ((adv_t)0x49b160)(ctx, 0);
    ((dtor_t)0x49a4d0)(ctx);
    probing = 0;
    return q == 1 ? 1 : q == 3 ? 0 : -1;
}
typedef int (__attribute__((thiscall)) *rpick_t)(DWORD, DWORD, DWORD);
int __attribute__((cdecl, used)) rpick_wrap(DWORD dlg, DWORD a1, DWORD a2) {
    DWORD ex[512]; int n = 0;
    ((lst_build_t)0x4748a0)(dlg + 0x6b4, 0x1e, 0);               // idle officers of this city: a region is approved if ANY of them would succeed
    int ne = lst_items(dlg + 0x6b4, ex, 512);
    memset(rgood, 0, sizeof rgood);
    for (int i = 0; i < RG_N + CT_N; i++) for (int e = 0; e < ne; e++) if (verdict_explore(ex[e], region_at(i)) == 1) { rgood[i] = 1; n++; break; }
    LOG("rpick dlg=%lx idle=%d good=%d", dlg, ne, n);
    { char s[1500]; int k = 0; for (int i = 0; i < RG_N + CT_N && k < 1400; i++) if (rgood[i]) k += sprintf(s + k, "%s ", (char *)(region_at(i) + 0x20)); LOG("rgood: %s", s); }
    marking_rg = 1;
    int r = ((rpick_t)0x4f4980)(dlg, a1, a2);
    marking_rg = 0;
    return r;
}
__asm__(".globl _rpick_detour\n_rpick_detour:\n pushl 8(%esp)\n pushl 8(%esp)\n pushl %ecx\n call _rpick_wrap\n addl $12,%esp\n ret $8\n");
extern void rpick_detour(void);
// column-text assign in the region list (call CString::operator=(const char*) at 0x43bcbd): src == region+0x20 -> name cell
void __attribute__((cdecl, used)) asg_wrap(DWORD cs, const char *src) {
    ((csasg_t)0x5c5fb0)(cs, src);
    if (!marking_rg) return;
    DWORD a = (DWORD)src - 0x20; int i = -1;
    if (a >= RG_BASE && a < RG_BASE + RG_N * RG_SIZE && (a - RG_BASE) % RG_SIZE == 0) i = (a - RG_BASE) / RG_SIZE;
    else if (a >= CT_BASE && a < CT_BASE + CT_N * CT_SIZE && (a - CT_BASE) % CT_SIZE == 0) i = RG_N + (a - CT_BASE) / CT_SIZE;
    if (i >= 0 && rgood[i]) ((cscat_t)0x5c6110)(cs, "\xa1\xb7");
}
__asm__(".globl _asg_detour\n_asg_detour:\n pushl 4(%esp)\n pushl %ecx\n call _asg_wrap\n addl $8,%esp\n ret $4\n");
extern void asg_detour(void);

static void watch_advisor(void) {
    static const BYTE e[] = {0xa6,0xb9,0xc1,0x7c,0xb1,0x4e,0xa6,0xb3,0xb1,0xd9,0xc0,0xf2}; // 此舉將有斬獲
    BYTE *p = findpat(e, sizeof e);
    LOG("advisor msg at %p", p);
    if (!p) return;
    DWORD base = ((DWORD)p & ~0xfff) - 0x1000;   // ponytail: assumes cluster spans ~3 pages around the explore msg
    for (int i = 0; i < 4; i++) pg[npg++] = base + i * 0x1000;
    AddVectoredExceptionHandler(1, veh);
    arm();
    LOG("guard armed %lx..%lx", pg[0], pg[npg-1] + 0xfff);
}

// ================= debug: timing-call tracer (IAT hooks; only when tt.on exists) =================
#define TT_N 6
static const DWORD tt_iat[TT_N] = {0x60f4d0, 0x60f114, 0x60f118, 0x60f144, 0x60f23c, 0x60f484};
static const char *tt_name[TT_N] = {"timeGetTime", "Sleep", "SleepEx", "GetTickCount", "QPC", "PeekMessage"};
static DWORD tt_orig[TT_N];
static struct { DWORD api, caller, n, arg; } tt_tab[512]; static int tt_nt; static CRITICAL_SECTION tt_cs; static int tt_cs_ok;
static void tt_hit(int api, DWORD caller, DWORD arg) {
    if (!tt_cs_ok) return;
    EnterCriticalSection(&tt_cs);
    int i; for (i = 0; i < tt_nt; i++) if (tt_tab[i].api == (DWORD)api && tt_tab[i].caller == caller) break;
    if (i == tt_nt && tt_nt < 512) { tt_tab[tt_nt].api = api; tt_tab[tt_nt].caller = caller; tt_tab[tt_nt].n = 0; tt_nt++; }
    if (i < 512) { tt_tab[i].n++; tt_tab[i].arg = arg; }
    LeaveCriticalSection(&tt_cs);
}
static DWORD WINAPI tt_timeGetTime(void) { tt_hit(0, (DWORD)__builtin_return_address(0), 0); return ((DWORD (WINAPI *)(void))tt_orig[0])(); }
static void WINAPI tt_Sleep(DWORD ms) { tt_hit(1, (DWORD)__builtin_return_address(0), ms); ((void (WINAPI *)(DWORD))tt_orig[1])(ms); }
static DWORD WINAPI tt_SleepEx(DWORD ms, BOOL a) { tt_hit(2, (DWORD)__builtin_return_address(0), ms); return ((DWORD (WINAPI *)(DWORD, BOOL))tt_orig[2])(ms, a); }
static DWORD WINAPI tt_GetTickCount(void) { tt_hit(3, (DWORD)__builtin_return_address(0), 0); return ((DWORD (WINAPI *)(void))tt_orig[3])(); }
static BOOL WINAPI tt_QPC(LARGE_INTEGER *q) { tt_hit(4, (DWORD)__builtin_return_address(0), 0); return ((BOOL (WINAPI *)(LARGE_INTEGER *))tt_orig[4])(q); }
static BOOL WINAPI tt_Peek(LPMSG m, HWND h, UINT a, UINT b, UINT c) { tt_hit(5, (DWORD)__builtin_return_address(0), 0); return ((BOOL (WINAPI *)(LPMSG, HWND, UINT, UINT, UINT))tt_orig[5])(m, h, a, b, c); }
static DWORD WINAPI tt_dump(LPVOID p) {
    static DWORD last[512];
    for (;;) {
        Sleep(3000);
        EnterCriticalSection(&tt_cs);
        char b[2000]; int n = 0;
        for (int i = 0; i < tt_nt && n < 1800; i++) if (tt_tab[i].n != last[i]) { n += sprintf(b + n, " %s@%lx:+%lu(a=%lu)", tt_name[tt_tab[i].api], tt_tab[i].caller, tt_tab[i].n - last[i], tt_tab[i].arg); last[i] = tt_tab[i].n; }
        LeaveCriticalSection(&tt_cs);
        if (n) LOG("tt%s", b);
    }
    return 0;
}
static void hook_tt(void) {
    if (GetFileAttributesA("tt.on") == INVALID_FILE_ATTRIBUTES) return;
    InitializeCriticalSection(&tt_cs); tt_cs_ok = 1;
    void *w[TT_N] = {tt_timeGetTime, tt_Sleep, tt_SleepEx, tt_GetTickCount, tt_QPC, tt_Peek};
    for (int i = 0; i < TT_N; i++) { DWORD o; tt_orig[i] = *(DWORD *)tt_iat[i]; VirtualProtect((void *)tt_iat[i], 4, PAGE_READWRITE, &o); *(DWORD *)tt_iat[i] = (DWORD)w[i]; VirtualProtect((void *)tt_iat[i], 4, o, &o); }
    CreateThread(NULL, 0, tt_dump, NULL, 0, NULL);
    LOG("tt tracer installed");
}

// ================= feature: 回合快進 (turn fast-forward) =================
// The game paces everything with timeGetTime/GetTickCount (fixed-step loop at 0x435b40). While the turn is being processed
// (progress phase: timeGetTime is called from 0x53d4fc / 0x53d690) we hand the game a virtual clock running SPD x faster.
// F10 = faster, F9 = slower; the current speed is shown in the window title.
static const int spd_tab[] = {1, 2, 3, 4, 6, 8, 12, 16}; static volatile int spd_i = 3;
static volatile DWORD prog_last; static volatile int cur_scale = 1;
typedef struct { DWORD r0, v0; int sc; } Vclk;
static Vclk vc_t = {0, 0, 1}, vc_g = {0, 0, 1};
static DWORD (WINAPI *real_tgt)(void), (WINAPI *real_gtc)(void);
static DWORD vclk(Vclk *c, DWORD real) {   // ponytail: no lock; clocks are only read by the game thread in practice
    if (c->sc != cur_scale) { c->v0 += (real - c->r0) * c->sc; c->r0 = real; c->sc = cur_scale; }
    return c->v0 + (real - c->r0) * c->sc;
}
static DWORD WINAPI sp_timeGetTime(void) {
    DWORD ra = (DWORD)__builtin_return_address(0), r = real_tgt();
    if (ra == 0x53d4fc || ra == 0x53d690) prog_last = r;
    int want = (r - prog_last < 700 && prog_last) ? spd_tab[spd_i] : 1;
    if (want != cur_scale) { vclk(&vc_t, r); cur_scale = want; }   // re-anchor timeGetTime clock before the switch (vc_g re-anchors lazily)
    return vclk(&vc_t, r);
}
static DWORD WINAPI sp_GetTickCount(void) { return vclk(&vc_g, real_gtc()); }
static void spd_title(HWND w) {
    static int shown = -1; int n = spd_tab[spd_i], on = cur_scale > 1;
    int key = n * 2 + on; if (key == shown) return; shown = key;
    wchar_t b[96]; if (n == 1) swprintf(b, L"三國志IXPK"); else swprintf(b, L"三國志IXPK　回合快進 ×%d%ls", n, on ? L" >>" : L"");
    SetWindowTextW(w, b);
}
static DWORD WINAPI spd_thread(LPVOID p) {
    int up = 0, dn = 0;
    for (;;) {
        Sleep(40);
        HWND w = FindWindowA("KOEI_SAN9WINDOW", NULL); if (!w) continue;
        if (GetForegroundWindow() == w) {
            int u = (GetAsyncKeyState(VK_F10) & 0x8000) != 0, d = (GetAsyncKeyState(VK_F9) & 0x8000) != 0;
            if (u && !up && spd_i < 7) { spd_i++; LOG("speed x%d", spd_tab[spd_i]); }
            if (d && !dn && spd_i > 0) { spd_i--; LOG("speed x%d", spd_tab[spd_i]); }
            up = u; dn = d;
        }
        spd_title(w);
    }
    return 0;
}
// ---- on-screen speed label: the game presents through GDI BitBlt/StretchDIBits; draw the label on the window DC after each present that touches it ----
static BOOL (WINAPI *real_bitblt)(HDC, int, int, int, int, HDC, int, int, DWORD);
static int (WINAPI *real_sdib)(HDC, int, int, int, int, int, int, int, int, const void *, const BITMAPINFO *, UINT, DWORD);
static HWND game_wnd; static HFONT ov_font;
#define OV_X 108
#define OV_Y 66
#define OV_W 150
#define OV_H 22
static void draw_label(HDC dc, int x, int y, int w, int h) {   // (x,y,w,h): the rectangle just presented
    int n = spd_tab[spd_i]; if (n == 1 && cur_scale == 1) return;   // label only while a speed-up is selected
    if (x > OV_X + OV_W || x + w < OV_X || y > OV_Y + OV_H || y + h < OV_Y) return;
    if (!ov_font) ov_font = CreateFontW(16, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, ANTIALIASED_QUALITY, 0, L"MS Gothic");
    int sv = SaveDC(dc);
    IntersectClipRect(dc, x, y, x + w, y + h);
    SelectObject(dc, ov_font); SetBkColor(dc, RGB(20, 20, 30)); SetTextColor(dc, cur_scale > 1 ? RGB(255, 220, 80) : RGB(200, 200, 200));
    wchar_t b[48]; int l = swprintf(b, L" 回合快進 ×%d %ls", n, cur_scale > 1 ? L"▶▶" : L"  ");
    RECT r = {OV_X, OV_Y, OV_X + OV_W, OV_Y + OV_H};
    ExtTextOutW(dc, OV_X, OV_Y + 2, ETO_OPAQUE | ETO_CLIPPED, &r, b, l, NULL);
    RestoreDC(dc, sv);
}
static int ov_is_game(HDC dc) { if (!game_wnd) game_wnd = FindWindowA("KOEI_SAN9WINDOW", NULL); return game_wnd && WindowFromDC(dc) == game_wnd; }
static BOOL WINAPI sp_BitBlt(HDC d, int x, int y, int w, int h, HDC s, int sx, int sy, DWORD op) {
    BOOL r = real_bitblt(d, x, y, w, h, s, sx, sy, op);
    if (ov_is_game(d)) draw_label(d, x, y, w, h);
    return r;
}
static int WINAPI sp_SDIB(HDC d, int x, int y, int w, int h, int a, int b, int c, int e, const void *p, const BITMAPINFO *bi, UINT u, DWORD op) {
    int r = real_sdib(d, x, y, w, h, a, b, c, e, p, bi, u, op);
    if (ov_is_game(d)) draw_label(d, x, y, w, h);
    return r;
}
static void hook_overlay(void) {
    DWORD o; DWORD *bb = (DWORD *)0x60f068, *sd = (DWORD *)0x60f070;
    real_bitblt = (void *)*bb; real_sdib = (void *)*sd;
    VirtualProtect(bb, 4, PAGE_READWRITE, &o); *bb = (DWORD)sp_BitBlt; VirtualProtect(bb, 4, o, &o);
    VirtualProtect(sd, 4, PAGE_READWRITE, &o); *sd = (DWORD)sp_SDIB; VirtualProtect(sd, 4, o, &o);
    LOG("overlay hook installed");
}

static void hook_speed(void) {
    if (GetFileAttributesA("no_speed.on") != INVALID_FILE_ATTRIBUTES) return;
    DWORD o; DWORD *t = (DWORD *)0x60f4d0, *g = (DWORD *)0x60f144;
    real_tgt = (void *)*t; real_gtc = (void *)*g;
    VirtualProtect(t, 4, PAGE_READWRITE, &o); *t = (DWORD)sp_timeGetTime; VirtualProtect(t, 4, o, &o);
    VirtualProtect(g, 4, PAGE_READWRITE, &o); *g = (DWORD)sp_GetTickCount; VirtualProtect(g, 4, o, &o);
    CreateThread(NULL, 0, spd_thread, NULL, 0, NULL);
    hook_overlay();
    LOG("speed hook installed");
}

static DWORD WINAPI init(LPVOID p) {
    LOG("init pid=%lu", GetCurrentProcessId());
    for (int i = 0; i < 600 && !FindWindowA("KOEI_SAN9WINDOW", NULL); i++) Sleep(100);
    Sleep(2000);
    LOG("window up");
    dump_text();
    hook_msg();
    hook_adv();
    hook_recruit_marks();
    hook_tt();
    hook_speed();
    // watch_advisor();  // ponytail: page-guard watcher off, hook_msg gives ids directly
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        lg = fopen("san9patch.log", "a");
        CreateThread(NULL, 0, init, NULL, 0, NULL);
    }
    return TRUE;
}
