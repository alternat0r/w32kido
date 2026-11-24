/*====================================================================================
 *  KIDO reproduction - PROCESS injector (built on host, run on VM)
 *
 *  The faithful delivery path for kido (an svchost-loaded DLL) maps the DLL and calls
 *  its entry point in a CLEAN process address space - there is no outer LoadLibrary on
 *  the stack, and nothing else holds the preferred base 0x10000000. A simple "map +
 *  call EP in this same process" harness is fragile (a prior worm run reserves
 *  0x10000000, so VirtualAlloc fails and the rebase goes wrong -> EP faults at its
 *  first instruction; both the ORIGINAL and the repro exhibit exactly this).
 *
 *  This injector does it properly:
 *     parent: CreateProcess(C:\Windows\System32\cmd.exe, /c exit, CREATE_SUSPENDED)
 *             -> map stage-1 into the child at 0x10000000 (fresh space, no conflict)
 *             -> resolve imports, apply relocations
 *             -> call the child's entry point (DLL_PROCESS_ATTACH) in the child thread
 *             -> ResumeThread (the worm's own threads then run)
 *             -> scan the TCP table for a LISTENING socket in 1024..9999 (the worm's
 *                HTTP server) and report it
 *
 *  Usage:  inject2_test.exe <path-to-stage1.dll>
 *====================================================================================*/
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#pragma comment(lib, "iphlpapi.lib")

static const char* VEH_PATH  = "C:\\rework\\kido_repro\\veh.txt";
static const char* DONE_PATH = "C:\\rework\\kido_repro\\child_done.txt";

static LONG WINAPI veh_stub(EXCEPTION_POINTERS* ep){
    if (ep->ExceptionRecord->ExceptionCode == 0xC0000005){
        static volatile LONG once = 0;
        if (InterlockedCompareExchange(&once,1,0)==0){
            HANDLE f = CreateFileA(VEH_PATH, FILE_APPEND_DATA, FILE_SHARE_READ|FILE_SHARE_WRITE,
                                   NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (f != INVALID_HANDLE_VALUE){
                char buf[520];
                DWORD esp = (DWORD)ep->ContextRecord->Esp;
                DWORD ret = *(DWORD*)esp;                 /* return address (pushed by call) */
                DWORD ret2 = *(DWORD*)(esp+4);
                DWORD ret3 = *(DWORD*)(esp+8);
                DWORD espv = *(DWORD*)(esp-4);            /* the call's operand (the target) */
                int n = sprintf(buf, "FAULT 0x%08lx  rip 0x%08lx  esp 0x%08lx  access=%lu(0=read 1=write 8=exec) addr=0x%08lx\n"
                                     "  eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x\n"
                                     "  [esp] ret=0x%08lx [esp+4]=0x%08lx [esp+8]=0x%08lx [esp-4]=0x%08lx\n",
                                (unsigned long)ep->ExceptionRecord->ExceptionCode,
                                (unsigned long)ep->ContextRecord->Eip,
                                (unsigned long)esp,
                                (unsigned long)ep->ExceptionRecord->ExceptionInformation[0],
                                (unsigned long)ep->ExceptionRecord->ExceptionInformation[1],
                                (unsigned)ep->ContextRecord->Eax,(unsigned)ep->ContextRecord->Ebx,
                                (unsigned)ep->ContextRecord->Ecx,(unsigned)ep->ContextRecord->Edx,
                                (unsigned)ep->ContextRecord->Esi,(unsigned)ep->ContextRecord->Edi,
                                (unsigned)ep->ContextRecord->Ebp,
                                (unsigned long)ret, (unsigned long)ret2, (unsigned long)ret3, (unsigned long)espv);
                /* query the faulting instruction's page */
                MEMORY_BASIC_INFORMATION mbi; ZeroMemory(&mbi,sizeof(mbi));
                if (VirtualQuery((LPCVOID)(ep->ContextRecord->Eip), &mbi, sizeof(mbi))){
                    char pb[160];
                    sprintf(pb,"  rip page: base=%08x prot=0x%x state=0x%x size=0x%x\n",
                            (unsigned)(DWORD)mbi.BaseAddress, (unsigned)mbi.Protect,
                            (unsigned)mbi.State, (unsigned)mbi.RegionSize);
                    n += sprintf(buf+n, pb);
                    /* also the data-access page if it's a data fault */
                    DWORD info = (DWORD)ep->ExceptionRecord->ExceptionInformation[0];
                    DWORD tgt  = (DWORD)ep->ExceptionRecord->ExceptionInformation[1];
                    MEMORY_BASIC_INFORMATION mbi2; ZeroMemory(&mbi2,sizeof(mbi2));
                    if (info && VirtualQuery((LPCVOID)tgt, &mbi2, sizeof(mbi2))){
                        char qb[160];
                        sprintf(qb,"  data page(%08x): base=%08x prot=0x%x state=0x%x\n",
                                (unsigned)tgt,(unsigned)(DWORD)mbi2.BaseAddress,(unsigned)mbi2.Protect,(unsigned)mbi2.State);
                        n += sprintf(buf+n, qb);
                    }
                }
                DWORD w; WriteFile(f, buf, n, &w, NULL);
                CloseHandle(f);
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char** argv){
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc<2){ fprintf(stderr,"usage: %s <stage1.dll>\n",argv[0]); return 2; }
    char path[MAX_PATH]; GetFullPathNameA(argv[1],MAX_PATH,path,NULL);
    char self[MAX_PATH]; GetModuleFileNameA(NULL, self, MAX_PATH);

    /* ---------------- CHILD MODE: the clean host ----------------
       Faithful delivery: in the original the wrapper (stage-1) is a *normal*
       module in svchost (LoadLibrary'd), so it holds its preferred base
       0x10000000 and its DllMain receives a real PEB-registered handle. Stage-1
       then reflectively maps stage-2 (same preferred base) at a relocated high
       address. We reproduce exactly that by LoadLibrary'ing stage-1 here (not a
       hand map): the worm's GetModuleFileNameA(hinst) resolves the on-disk path
       and g_path ends in ".dll", so the worm treats itself as a service DLL. */
    if (GetEnvironmentVariableA("KIDO_CHILD", NULL, 0) != NULL){
        AddVectoredExceptionHandler(1, veh_stub);
        FILE* mark = fopen(DONE_PATH,"w"); if (mark) fclose(mark);   /* signal the parent */
        HMODULE s1 = LoadLibraryA(path);
        if (!s1){
            char ib[96]; sprintf(ib,"LOADLIB1 FAIL err=%lu\n",GetLastError());
            HANDLE ff=CreateFileA(VEH_PATH,FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
            if(ff){DWORD w;WriteFile(ff,ib,(DWORD)strlen(ib),&w,NULL);CloseHandle(ff);}
            return 4;
        }
        for (;;){ Sleep(1000); }   /* keep the process alive so the worm thread runs */
        return 0;
    }

    /* ---------------- PARENT MODE: spawn + monitor ---------------- */
    DeleteFileA(DONE_PATH);
    SetEnvironmentVariableA("KIDO_CHILD", "1");   /* child inherits this (no recursion) */
    char cmdline[1024];
    sprintf(cmdline, "\"%s\" \"%s\"", self, path);
    STARTUPINFOA si; ZeroMemory(&si,sizeof(si)); si.cb=sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi,sizeof(pi));
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)){
        printf("CreateProcess fail err=%lu\n", GetLastError()); return 5;
    }
    printf("child (clean host) pid=%lu\n", pi.dwProcessId);

    for (int i=0;i<50 && (GetFileAttributesA(DONE_PATH)==INVALID_FILE_ATTRIBUTES); i++) Sleep(100);
    printf("child ready, worm chain running\n");

    int seen=0;
    /* The worm's first HTTP bind is delayed by a ~10s "stop SharedAccess" sleep
       (kido_bind_random_port), so scan for up to 40s before giving up. */
    for (int i=1;i<=40;i++){
        Sleep(1000);
        DWORD s=0; GetExtendedTcpTable(NULL,&s,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);
        if (!s) continue;
        unsigned char* b=(unsigned char*)GlobalAlloc(GMEM_MOVEABLE,s);
        if (GetExtendedTcpTable(b,&s,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0)!=NO_ERROR){ GlobalFree(b); continue; }
        MIB_TCPTABLE_OWNER_PID* t=(MIB_TCPTABLE_OWNER_PID*)b;
        for (DWORD i2=0;i2<t->dwNumEntries;i2++){
            MIB_TCPROW_OWNER_PID* r=&t->table[i2];
            if (r->dwState!=2) continue;
            unsigned short port=(unsigned short)(r->dwLocalPort>>16);
            if (port>=1024 && port<=9999){ printf("  [t=%2ds] worm HTTP LISTEN port %u (pid %lu)\n", i, port, r->dwOwningPid); seen=1; }
        }
        GlobalFree(b);
        if (seen) break;
    }
    DWORD ec=0xFFFFFFFF; GetExitCodeProcess(pi.hProcess,&ec);
    if (ec==0xFFFFFFFF) printf("VERDICT: child pid %lu still RUNNING (worm host alive)\n", pi.dwProcessId);
    else printf("VERDICT: child pid %lu exited code 0x%08lx\n", pi.dwProcessId, ec);

    /* final: dump the child's diagnostic traces here so one driver run captures all */
    const char* trfiles[] = {"worm_trace.txt","loader_ep.txt","loader_map.txt","guard.txt","worm_crash.txt"};
    for (int i=0;i<5;i++){
        char tf[64]; sprintf(tf,"C:\\rework\\kido_repro\\%s",trfiles[i]);
        FILE* f=fopen(tf,"r");
        if (f){ printf("[child:%s]\n",trfiles[i]); char l[300]; while(fgets(l,300,f)) fputs(l,stdout); fclose(f); }
    }
    /* FAULT line from veh.txt */
    {
        FILE* f=fopen("C:\\rework\\kido_repro\\veh.txt","r");
        if (f){ char l[400]; while(fgets(l,400,f)) if (strstr(l,"FAULT")) printf("[child:veh] %s",l); fclose(f); }
    }
    fflush(stdout);

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return 0;
}
