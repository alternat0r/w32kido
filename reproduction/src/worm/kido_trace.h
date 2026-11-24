#ifndef KIDO_TRACE_H
#define KIDO_TRACE_H
/* Lightweight step tracing for VM runs. Writes to C:\rework\kido_repro\worm_trace.txt.
   Only active when the file path is writable; otherwise a no-op. */
#include <windows.h>
#include <stdio.h>

#define KIDO_TRACE_PATH "C:\\rework\\kido_repro\\worm_trace.txt"

static void kido_trace(const char* step)
{
    HANDLE f = CreateFileA(KIDO_TRACE_PATH, FILE_APPEND_DATA, FILE_SHARE_READ|FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    char buf[128];
    int n = sprintf(buf, "[%lu ms] %s\n", GetTickCount(), step);
    DWORD w; WriteFile(f, buf, n, &w, NULL);
    CloseHandle(f);
}

/* One-shot crash logger + minidump for any exception in the worm's threads.
   Returns EXCEPTION_CONTINUE_SEARCH (never swallows the fault). */
#include <dbghelp.h>
static LONG WINAPI kido_worm_veh(EXCEPTION_POINTERS* ep)
{
    static volatile LONG once = 0;
    if (ep->ExceptionRecord->ExceptionCode == 0xC0000005 &&
        InterlockedCompareExchange(&once, 1, 0) == 0){
        HANDLE f = CreateFileA("C:\\rework\\kido_repro\\worm_crash.txt", FILE_APPEND_DATA,
            FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE){
            char b[256];
            int n = sprintf(b, "WORM FAULT 0x%08lx rip=0x%08lx esp=0x%08lx access=%lu addr=0x%08lx\n",
                ep->ExceptionRecord->ExceptionCode, ep->ContextRecord->Eip,
                ep->ContextRecord->Esp, ep->ExceptionRecord->ExceptionInformation[0],
                ep->ExceptionRecord->ExceptionInformation[1]);
            DWORD w; WriteFile(f, b, n, &w, NULL);
            CloseHandle(f);
        }
        HANDLE hProc = GetCurrentProcess();
        HANDLE hThr  = GetCurrentThread();
        HANDLE hf = CreateFileA("C:\\rework\\kido_repro\\worm_crash.dmp", GENERIC_WRITE, 0,
            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE){
            MINIDUMP_TYPE t = (MINIDUMP_TYPE)(MiniDumpWithFullMemory|MiniDumpWithThreadInfo);
            if (!MiniDumpWriteDump(hProc, GetProcessId(hThr), hf, t, NULL, NULL, NULL))
                CloseHandle(hf);
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
#pragma comment(lib, "dbghelp.lib")
#endif
