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

static DWORD prot_from_scn(DWORD s){
    DWORD p=PAGE_READONLY;
    if (s&0x20000000) p=PAGE_EXECUTE_READ;
    if (s&0x40000000) p=PAGE_EXECUTE_READWRITE;
    if (s&0x80000000){ if (s&0x20000000) p=PAGE_EXECUTE_READWRITE; else p=PAGE_READWRITE; }
    return p;
}

/* map a PE image into the process at a desired base; resolve imports; rebase.
   desired == 0 uses the image's preferred base. We deliberately map stage-1 at a
   HIGH base (not its preferred 0x10000000) so that the reflectively-mapped stage-2
   (which also wants 0x10000000) lands on its preferred base cleanly - exactly as in
   the real delivery, where the outer host holds stage-1 and stage-2 claims 0x10000000. */
static HMODULE map_pe(const uint8_t* img, size_t len, DWORD desired){
    if (len < 0x40) return NULL;
    DWORD el = *(DWORD*)(img+0x3C);
    const IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(img+el);
    if (nt->Signature != 0x00004550) return NULL;
    const IMAGE_OPTIONAL_HEADER32* opt = &nt->OptionalHeader;
    if (opt->Magic != 0x10b) return NULL;
    DWORD image_size = opt->SizeOfImage, hdr = opt->SizeOfHeaders;
    LPVOID base = VirtualAlloc((LPVOID)(ULONG_PTR)(desired? desired : opt->ImageBase), image_size, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    if (!base) base = VirtualAlloc(NULL, image_size, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    if (!base) return NULL;
    HMODULE actual = (HMODULE)(ULONG_PTR)base;
    memcpy(base, img, hdr);
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i=0;i<nt->FileHeader.NumberOfSections;++i,++sec)
        if (sec->SizeOfRawData)
            memcpy((LPBYTE)base+sec->VirtualAddress, img+sec->PointerToRawData, sec->SizeOfRawData);
    /* imports */
    if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress){
        IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)((LPBYTE)base+opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        for (; imp->Name; ++imp){
            HMODULE dll = LoadLibraryA((const CHAR*)((LPBYTE)base+imp->Name));
            if (!dll){
                char ib[96]; sprintf(ib,"IMPORT FAIL: %s (err %lu)\n",
                    (const char*)((LPBYTE)base+imp->Name), GetLastError());
                HANDLE ff=CreateFileA(VEH_PATH,FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
                if(ff){DWORD w;WriteFile(ff,ib,(DWORD)strlen(ib),&w,NULL);CloseHandle(ff);}
                return actual;
            }
            IMAGE_THUNK_DATA* ilt=(IMAGE_THUNK_DATA*)((LPBYTE)base+imp->FirstThunk);
            IMAGE_THUNK_DATA* iat=(IMAGE_THUNK_DATA*)((LPBYTE)base+(imp->OriginalFirstThunk?imp->OriginalFirstThunk:imp->FirstThunk));
            for (; iat->u1.AddressOfData; ++iat,++ilt){
                if (iat->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                    ilt->u1.Function=(DWORD)(ULONG_PTR)GetProcAddress(dll,(LPCSTR)(iat->u1.Ordinal&0xFFFF));
                else
                    ilt->u1.Function=(DWORD)(ULONG_PTR)GetProcAddress(dll,((IMAGE_IMPORT_BY_NAME*)((LPBYTE)base+iat->u1.AddressOfData))->Name);
            }
        }
    }
    /* relocations (only if we did not get the preferred base) */
    if ((DWORD_PTR)actual != (DWORD_PTR)(ULONG_PTR)opt->ImageBase &&
        opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress){
        LONG delta=(LONG)((DWORD_PTR)actual-(DWORD_PTR)(ULONG_PTR)opt->ImageBase);
        IMAGE_BASE_RELOCATION* rel=(IMAGE_BASE_RELOCATION*)((LPBYTE)base+opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        for (; rel->VirtualAddress; rel=(IMAGE_BASE_RELOCATION*)((LPBYTE)rel+rel->SizeOfBlock)){
            const WORD* e=(const WORD*)(rel+1); DWORD cnt=(rel->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/2;
            for (DWORD i=0;i<cnt;i++) if ((e[i]>>12)==3) *(DWORD*)((LPBYTE)base+rel->VirtualAddress+(e[i]&0xFFF))+=delta;
        }
    }
    /* section protections */
    sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i=0;i<nt->FileHeader.NumberOfSections;++i,++sec)
        if (sec->Misc.VirtualSize) VirtualProtect((LPBYTE)base+sec->VirtualAddress, sec->Misc.VirtualSize, prot_from_scn(sec->Characteristics), NULL);
    return actual;
}

int main(int argc, char** argv){
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc<2){ fprintf(stderr,"usage: %s <stage1.dll>\n",argv[0]); return 2; }
    char path[MAX_PATH]; GetFullPathNameA(argv[1],MAX_PATH,path,NULL);
    char self[MAX_PATH]; GetModuleFileNameA(NULL, self, MAX_PATH);

    /* ---------------- CHILD MODE: the clean host ---------------- */
    if (GetEnvironmentVariableA("KIDO_CHILD", NULL, 0) != NULL){
        AddVectoredExceptionHandler(1, veh_stub);
        FILE* mark = fopen(DONE_PATH,"w"); if (mark) fclose(mark);   /* signal the parent */
        HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf==INVALID_HANDLE_VALUE){ return 3; }
        DWORD fsz = GetFileSize(hf, NULL);
        HANDLE hm = CreateFileMappingA(hf, NULL, PAGE_READONLY, 0, 0, NULL);
        const uint8_t* view = (const uint8_t*)MapViewOfFile(hm, FILE_MAP_READ, 0, 0, 0);
        uint8_t* img=(uint8_t*)malloc(fsz);
        memcpy(img, view, fsz);
        UnmapViewOfFile(view); CloseHandle(hm); CloseHandle(hf);
        /* Map stage-1 at a HIGH base so its reflectively-loaded stage-2 (UPX,
           non-relocatable stub, MUST be at 0x10000000) can claim that base cleanly.
           In real delivery svchost holds stage-1 at an ASLR base and stage-2 owns
           0x10000000. stage-1 itself is fully relocatable, so rebasing is exact. */
        HMODULE base = map_pe(img, fsz, 0x50000000);
        if (!base){ return 4; }
        const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(img + *(DWORD*)(img+0x3C));
        DWORD eprva = nt->OptionalHeader.AddressOfEntryPoint;
        /* Also read the EP straight from the mapped image (belt & suspenders). */
        const IMAGE_NT_HEADERS* nt2 = (const IMAGE_NT_HEADERS*)((LPBYTE)base + *(DWORD*)(img+0x3C));
        DWORD eprva2 = nt2->OptionalHeader.AddressOfEntryPoint;
        MEMORY_BASIC_INFORMATION mbi; ZeroMemory(&mbi,sizeof(mbi));
        VirtualQuery((LPVOID)((LPBYTE)base+eprva), &mbi, sizeof(mbi));
        BYTE* e = (BYTE*)((LPBYTE)base+eprva);
        HANDLE lf = CreateFileA(VEH_PATH, FILE_APPEND_DATA, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (lf!=INVALID_HANDLE_VALUE){
            char db[220];
            sprintf(db,"DIAG elfanew=0x%x eprva=0x%x eprva2=0x%x base=0x%p ep_addr=0x%p prot=0x%x state=0x%x\n",
                *(DWORD*)(img+0x3C), eprva, eprva2, base, (void*)(base+eprva), mbi.Protect, mbi.State);
            DWORD w; WriteFile(lf,db,(DWORD)strlen(db),&w,NULL);
            char db2[64]; sprintf(db2,"  epbytes(mapped): %02x %02x %02x %02x %02x %02x\n", e[0],e[1],e[2],e[3],e[4],e[5]);
            WriteFile(lf,db2,(DWORD)strlen(db2),&w,NULL);
            /* EP bytes straight from the file buffer (ground truth) */
            char db3[96]; sprintf(db3,"  epbytes(file  img+0x%x): %02x %02x %02x %02x %02x %02x\n",
                eprva, img[eprva],img[eprva+1],img[eprva+2],img[eprva+3],img[eprva+4],img[eprva+5]);
            WriteFile(lf,db3,(DWORD)strlen(db3),&w,NULL); CloseHandle(lf);
        }
        /* force correct protection on EVERY section (map_pe may have returned early
           before its protection loop if an import's LoadLibraryA failed; the EP is in
           .text, so it MUST be executable or instruction-fetch faults). */
        {
            const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
            for (WORD i=0;i<nt->FileHeader.NumberOfSections;++i,++sec){
                if (!sec->Misc.VirtualSize) continue;
                DWORD oldp;
                BOOL ok = VirtualProtect((LPBYTE)base+sec->VirtualAddress, sec->Misc.VirtualSize,
                                         prot_from_scn(sec->Characteristics), &oldp);
                char pb[96];
                sprintf(pb,"  VP %s VA 0x%06x size 0x%x -> 0x%x ok=%d old=0x%x\n",
                        (char*)sec->Name, sec->VirtualAddress, sec->Misc.VirtualSize,
                        prot_from_scn(sec->Characteristics), ok, oldp);
                HANDLE pf=CreateFileA(VEH_PATH,FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
                if(pf){DWORD w;WriteFile(pf,pb,(DWORD)strlen(pb),&w,NULL);CloseHandle(pf);}
            }
            /* re-query the EP page after forcing */
            MEMORY_BASIC_INFORMATION m2; VirtualQuery((LPVOID)((LPBYTE)base+eprva),&m2,sizeof(m2));
            char qb[96]; sprintf(qb,"  post-VP EP page protect=0x%x state=0x%x\n", m2.Protect, m2.State);
            HANDLE qf=CreateFileA(VEH_PATH,FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
            if(qf){DWORD w;WriteFile(qf,qb,(DWORD)strlen(qb),&w,NULL);CloseHandle(qf);}
        }
        /* dump mapped .text start (0x1000) and the real EP (0xa48) to confirm the copy */
        {
            HANDLE lf=CreateFileA(VEH_PATH,FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
            if(lf){
                char b[160];
                sprintf(b,"  mapped text@0x1000: %02x %02x %02x %02x  mapped EP@0xa48: %02x %02x %02x %02x\n",
                    ((BYTE*)base)[0x1000],((BYTE*)base)[0x1001],((BYTE*)base)[0x1002],((BYTE*)base)[0x1003],
                    ((BYTE*)base)[0x1a48],((BYTE*)base)[0x1a49],((BYTE*)base)[0x1a4a],((BYTE*)base)[0x1a4b]);
                DWORD w; WriteFile(lf,b,(DWORD)strlen(b),&w,NULL); CloseHandle(lf);
            }
        }
        typedef void(WINAPI* EPFn)(HINSTANCE, DWORD, LPVOID);
        ((EPFn)((LPBYTE)base + eprva))((HINSTANCE)base, 1, NULL);   /* runs the whole chain */
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
