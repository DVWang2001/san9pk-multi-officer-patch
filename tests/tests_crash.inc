// last-resort handler: an unguarded fault inside a test is reported (with a short call chain) instead of silently killing the host
static int n_pass, n_fail;
static LONG CALLBACK crash_log(EXCEPTION_POINTERS *e) {
    DWORD code = e->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_ILLEGAL_INSTRUCTION) {
        fprintf(out, "UNGUARDED FAULT code=%lx eip=%lx addr=%lx stack:", code, e->ContextRecord->Eip,
                e->ExceptionRecord->NumberParameters > 1 ? (DWORD)e->ExceptionRecord->ExceptionInformation[1] : 0);
        DWORD *sp = (DWORD *)e->ContextRecord->Esp; int n = 0;
        for (int k = 0; k < 600 && n < 10; k++) if (!IsBadReadPtr(sp + k, 4) && sp[k] >= 0x401000 && sp[k] < 0x60e30a) { fprintf(out, " %lx", sp[k]); n++; }
        fputc(10, out);
        fprintf(out, "RESULT pass=%d fail=%d (aborted)\n", n_pass, n_fail + 1);
        ExitProcess(3);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
