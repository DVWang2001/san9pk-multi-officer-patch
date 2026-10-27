// ---- test cases (included by tests.c before run()) ----
static int n_pass, n_fail;
#define CHECK(c, ...) do { if (c) n_pass++; else { n_fail++; fprintf(out, "FAIL line %d: ", __LINE__); fprintf(out, __VA_ARGS__); fputc(10, out); } } while (0)

// fake game list: head pointer at +4, count at +0xc; nodes {next, prev, data}
static void mk_list(BYTE *l, DWORD (*nodes)[3], DWORD *vals, int n) {
    memset(l, 0, 0x40);
    for (int i = 0; i < n; i++) { nodes[i][0] = i + 1 < n ? (DWORD)nodes[i + 1] : 0; nodes[i][1] = i ? (DWORD)nodes[i - 1] : 0; nodes[i][2] = vals[i]; }
    *(DWORD *)(l + 4) = n ? (DWORD)nodes[0] : 0; *(int *)(l + 0xc) = n;
}

static void t_sort_front(void) {
    static BYTE l[0x40]; static DWORD nodes[512][3], vals[512], pre[512], got[512], exp[512];
    unsigned seed = 12345;
    for (int trial = 0; trial < 500; trial++) {
        seed = seed * 1103515245 + 12345; int n = (seed >> 16) % 301;
        for (int i = 0; i < n; i++) vals[i] = 0x1000 + i * 8;
        int np = 0; for (int i = 0; i < n; i++) { seed = seed * 1103515245 + 12345; if ((seed >> 16) % 3 == 0) pre[np++] = vals[i]; }
        for (int i = 0; i + 1 < np; i += 2) { DWORD t = pre[i]; pre[i] = pre[i + 1]; pre[i + 1] = t; }   // the order inside pre must not matter
        mk_list(l, (void *)nodes, vals, n);
        sort_front((DWORD)l, pre, np);
        int k = lst_items((DWORD)l, got, 512), m = 0;
        for (int i = 0; i < n; i++) { int in = 0; for (int j = 0; j < np; j++) if (pre[j] == vals[i]) in = 1; if (in) exp[m++] = vals[i]; }
        for (int i = 0; i < n; i++) { int in = 0; for (int j = 0; j < np; j++) if (pre[j] == vals[i]) in = 1; if (!in) exp[m++] = vals[i]; }
        int same = (k == n); for (int i = 0; i < n && same; i++) if (got[i] != exp[i]) same = 0;
        CHECK(same, "sort_front trial %d n=%d np=%d", trial, n, np);
        if (!same) break;
    }
    // two-tier use (target pickers): a second sort moves its items ahead and keeps the earlier order inside each group
    { DWORD v[6] = {10, 20, 30, 40, 50, 60}, a[3] = {20, 40, 60}, b[1] = {60}; mk_list(l, (void *)nodes, v, 6); sort_front((DWORD)l, a, 3); sort_front((DWORD)l, b, 1);
      int k = lst_items((DWORD)l, got, 512); DWORD want[6] = {60, 20, 40, 10, 30, 50};
      int same = k == 6; for (int i = 0; i < 6; i++) if (got[i] != want[i]) same = 0; CHECK(same, "two-tier order"); }
}

static void t_speed_clock(void) {
    Vclk c = {0, 0, 1}; cur_scale = 1;
    CHECK(vclk(&c, 1000) == 1000, "x1 identity");
    CHECK(vclk(&c, 1500) == 1500, "x1 identity 2");
    cur_scale = 4; DWORD a = vclk(&c, 2000); CHECK(a == 2000, "continuous at switch (%lu)", a);
    DWORD b = vclk(&c, 2100); CHECK(b - a == 400, "x4 slope (%lu)", b - a);
    cur_scale = 1; DWORD d = vclk(&c, 2200); CHECK(d == b + 400, "continuous switching back (%lu vs %lu)", d, b + 400);
    DWORD e = vclk(&c, 2300); CHECK(e - d == 100, "back to x1 slope");
    cur_scale = 16; DWORD f0 = vclk(&c, 0xfffffff0u); DWORD f1 = vclk(&c, 0x10u); CHECK(f1 - f0 == 16u * 0x20u, "tick wrap-around keeps slope (%lu)", f1 - f0);
    cur_scale = 1;
}

static void t_verdict_vs_game(void) {
    FILE *t = fopen("snap_truth.txt", "r"); if (!t) { CHECK(0, "no snap_truth.txt"); return; }
    int e, g, q, n = 0, bad = 0, ngood = 0;
    while (fscanf(t, "%d %d %d", &e, &g, &q) == 3) {
        int r = verdict(OFF_BASE + e * OFF_SIZE, OFF_BASE + g * OFF_SIZE), want = q == 1 ? 1 : q == 3 ? 0 : -1; n++;
        if (want == 1) ngood++;
        if (r != want) { bad++; if (bad <= 5) fprintf(out, "  verdict mismatch %d,%d game=%d host=%d\n", e, g, want, r); }
    }
    fclose(t);
    CHECK(n > 3000 && bad == 0, "patch verdict() vs in-game advisor: %d pairs, %d mismatches, %d good", n, bad, ngood);
}


// mark_targets() against the verdicts the real game produced (snap_truth.txt): idle officers = the executors in the file, targets = the other officers in it
static DWORD tt_idle[16]; static int tt_nidle;
static int idle_fake(DWORD dlg, int ltype, DWORD *ex, int max) { for (int i = 0; i < tt_nidle; i++) ex[i] = tt_idle[i]; return tt_nidle; }
static void t_mark_targets(void) {
    static int truth_q[2000][2000]; static int execs[16], nex, tg[2000], ntg; int e, g, q;
    FILE *t = fopen("snap_truth.txt", "r"); if (!t) { CHECK(0, "no snap_truth.txt"); return; }
    for (int i = 0; i < 2000; i++) for (int k = 0; k < 2000; k++) truth_q[i][k] = -9;
    while (fscanf(t, "%d %d %d", &e, &g, &q) == 3) {
        int a; for (a = 0; a < nex && execs[a] != e; a++); if (a == nex && nex < 16) execs[nex++] = e;
        int b; for (b = 0; b < ntg && tg[b] != g; b++); if (b == ntg && ntg < 2000) tg[ntg++] = g;
        truth_q[e][g] = q == 1 ? 1 : q == 3 ? 0 : -1;
    }
    fclose(t);
    tt_nidle = nex; for (int i = 0; i < nex; i++) tt_idle[i] = OFF_BASE + execs[i] * OFF_SIZE;
    DWORD c[512], pre[512], pre2[512]; int nc = 0, np2 = 0, cidx[512];
    for (int b = 0; b < ntg && nc < 512; b++) { int isx = 0; for (int a = 0; a < nex; a++) if (execs[a] == tg[b]) isx = 1; if (!isx) { c[nc] = OFF_BASE + tg[b] * OFF_SIZE; cidx[nc++] = tg[b]; } }
    idle_provider = idle_fake;
    int bi = 0, bestn = -1;   // "current executor" = the one the game says can recruit the most of these targets
    for (int a = 0; a < nex; a++) { int cnt = 0; for (int b = 0; b < nc; b++) cnt += truth_q[execs[a]][cidx[b]] == 1; if (cnt > bestn) { bestn = cnt; bi = a; } }
    int np = mark_targets(0, 0x1e, 1, tt_idle[bi], c, nc, pre, pre2, &np2);
    int want = 0, want2 = 0, mism = 0;
    for (int b = 0; b < nc; b++) {
        int any = 0; for (int a = 0; a < nex; a++) if (truth_q[execs[a]][cidx[b]] == 1) any = 1;
        int isg = good[cidx[b]];
        if (any != isg) mism++;
        want += any; want2 += truth_q[execs[bi]][cidx[b]] == 1;
    }
    CHECK(mism == 0, "good[] disagrees with the game's own verdicts for %d targets", mism);
    CHECK(np == want && np2 == want2, "approved %d (game says %d), ok for the current executor %d (game says %d)", np, want, np2, want2);
    int only_others = np - np2;
    fprintf(out, "  info: %d targets, %d idle executors, approved %d, ok for current executor %d, ok only for another officer %d\n", nc, nex, np, np2, only_others);
    CHECK(np > 0 && np2 <= np, "tiers sane");
    CHECK(only_others > 0, "no target that only another officer can recruit: the regression case is not exercised by this snapshot");
    // tier order after the two sorts used in pick_wrap: current-executor-ok first, then others-ok, then the rest
    { static BYTE l[0x40]; static DWORD nodes[512][3], got[512]; mk_list(l, (void *)nodes, c, nc); sort_front((DWORD)l, pre, np); sort_front((DWORD)l, pre2, np2);
      int k = lst_items((DWORD)l, got, 512), ok = k == nc, phase = 0;
      for (int i = 0; i < k && ok; i++) { int idx = (got[i] - OFF_BASE) / OFF_SIZE; int tier = truth_q[execs[bi]][idx] == 1 ? 0 : good[idx] ? 1 : 2; if (tier < phase) ok = 0; if (tier > phase) phase = tier; }
      CHECK(ok, "list order after the two-tier sort"); }
    idle_provider = idle_default;
}

static void run_tests(void) {
    t_sort_front(); t_speed_clock(); t_verdict_vs_game(); t_mark_targets();
    fprintf(out, "RESULT pass=%d fail=%d\n", n_pass, n_fail);
}
