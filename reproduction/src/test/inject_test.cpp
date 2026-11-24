/*====================================================================================
 *  KIDO reproduction - manual-map + direct-EP driver (built on host, run on VM)
 *
 *  Usage:  inject_test.exe <path-to-stage1.dll>
 *
 *  The original kido.sample (and this reproduction) is a reflective loader whose
 *  DllMain calls LoadLibraryA to resolve the embedded stage-2's imports. Calling it
 *  through an outer LoadLibraryA re-enters the system loader while that load still
 *  holds the loader critical section -> ERROR_NO_MORE_FILES (1114). Both the ORIGINAL
 *  and the reproduction exhibit this exactly (verified: kido.sample -> 1114 too).
 *
 *  The real delivery path is the PE loader / an injector, which maps the DLL and calls
 *  its entry point directly (no outer LoadLibrary on the stack). This driver does the
 *  same thing so we can observe the full 3-layer chain actually run:
 *
 *      manually map stage-1  ->  call its entry point (PROCESS_ATTACH)
 *        stage-1 DllMain: decode + reflectively map stage-2 + resolve imports
 *          stage-2 UPX stub: decompress + resolve worm imports + jump to worm
 *            worm DllMain: keyboard guard + single-instance mutex + spawn main thread
 *              main thread: ... start HTTP server on a random port 1024..9999
 *
 *  After the EP returns, we scan the TCP table for a LISTENING socket in 1024..9999.
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

/* VEH: catch access violations from ANY thread (the worm spawns a main thread;
   a crash there would otherwise take the whole process down silently). */
static LONG WINAPI veh(EXCEPTION_POINTERS* ep){
    if (ep->ExceptionRecord->ExceptionCode == 0xC0000005){
        static volatile LONG once = 0;
        if (InterlockedCompareExchange(&once, 1, 0) == 0){
            fprintf(stderr, "[VEH] EXC 0x%08lx addr 0x%p (context rip %p)\n",
                    ep->ExceptionRecord->ExceptionCode,
                    ep->ExceptionRecord->ExceptionAddress,
                    (void*)ep->ContextRecord->Eip);
            fflush(stderr);
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

/* Map a PE image file at its preferred base; resolve imports; return base or NULL. */
static HMODULE map_pe(const uint8_t* img, size_t len){
    if (len < 0x40) return NULL;
    printf("  [map_pe] entry len=%u\n", (unsigned)len); fflush(stdout);
    DWORD el = *(const DWORD*)(img+0x3C);
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(img+el);
    printf("  [map_pe] e_lfanew=0x%x sig=0x%x\n", el, nt->Signature); fflush(stdout);
    if (nt->Signature != 0x00004550) return NULL;
    const IMAGE_OPTIONAL_HEADER32* opt = &nt->OptionalHeader;
    if (opt->Magic != 0x10b) return NULL;
    DWORD image_size = opt->SizeOfImage, hdr = opt->SizeOfHeaders;
    printf("  [map_pe] nsec=%d base=0x%08x imgsize=0x%x hdr=0x%x\n",
           nt->FileHeader.NumberOfSections, opt->ImageBase, image_size, hdr); fflush(stdout);
    LPVOID base = VirtualAlloc((LPVOID)(ULONG_PTR)opt->ImageBase, image_size, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    if (!base) base = VirtualAlloc(NULL, image_size, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    if (!base) return NULL;
    printf("  [map_pe] base=0x%p, copying headers\n", base); fflush(stdout);
    memcpy(base, img, hdr);
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i=0;i<nt->FileHeader.NumberOfSections;++i,++sec){
        if (sec->SizeOfRawData)
            memcpy((LPBYTE)base+sec->VirtualAddress, img+sec->PointerToRawData, sec->SizeOfRawData);
    }
    printf("  [map_pe] sections copied\n"); fflush(stdout);
    /* resolve imports */
    if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress){
        IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)((LPBYTE)base + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        for (; imp->Name; ++imp){
            HMODULE dll = LoadLibraryA((const CHAR*)((LPBYTE)base+imp->Name));
            if (!dll) return (HMODULE)base;
            IMAGE_THUNK_DATA* ilt = (IMAGE_THUNK_DATA*)((LPBYTE)base+imp->FirstThunk);
            IMAGE_THUNK_DATA* iat = (IMAGE_THUNK_DATA*)((LPBYTE)base+(imp->OriginalFirstThunk?imp->OriginalFirstThunk:imp->FirstThunk));
            for (; iat->u1.AddressOfData; ++iat,++ilt){
                if (iat->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                    ilt->u1.Function = (DWORD)(ULONG_PTR)GetProcAddress(dll,(LPCSTR)(iat->u1.Ordinal&0xFFFF));
                else
                    ilt->u1.Function = (DWORD)(ULONG_PTR)GetProcAddress(dll, ((IMAGE_IMPORT_BY_NAME*)((LPBYTE)base+iat->u1.AddressOfData))->Name);
            }
        }
    }
    /* relocations if rebased */
    if ((DWORD_PTR)base != opt->ImageBase && opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress){
        LONG delta=(LONG)((DWORD_PTR)base-opt->ImageBase);
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
    return (HMODULE)base;
}

int main(int argc, char** argv){
    setvbuf(stdout, NULL, _IONBF, 0);
    AddVectoredExceptionHandler(1, veh);
    if (argc<2){ fprintf(stderr,"usage: %s <stage1.dll>\n",argv[0]); return 2; }
    char path[MAX_PATH]; GetFullPathNameA(argv[1],MAX_PATH,path,NULL);
    HANDLE hf = CreateFileA(path, GENERIC_READ,
                            FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE){ printf("CreateFile fail err=%lu\n", GetLastError()); return 3; }
    DWORD fsz = GetFileSize(hf, NULL);
    printf("file size: %lu bytes\n", fsz);
    uint8_t* img = (uint8_t*)malloc(fsz ? fsz : 1);
    if (!img){ printf("malloc fail\n"); CloseHandle(hf); return 3; }
    {
        DWORD total = 0, rd = 0;
        BOOL ok = TRUE;
        while (total < fsz){
            rd = 0;
            if (!ReadFile(hf, img + total, fsz - total, &rd, NULL)){
                ok = FALSE; break;
            }
            if (rd == 0) break;
            total += rd;
        }
        if (!ok || total != fsz){ printf("ReadFile stop: total=%lu err=%lu\n", total, GetLastError()); CloseHandle(hf); return 3; }
    }
    CloseHandle(hf);
    printf("  [main] read %lu bytes, img[0]=0x%02x, calling map_pe\n", (unsigned)fsz, img[0]); fflush(stdout);

    HMODULE base = map_pe(img, fsz);
    if (!base){ printf("map stage-1 FAILED\n"); return 4; }
    printf("stage-1 mapped at 0x%p\n", base);

    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(img + *(DWORD*)(img+0x3C));
    DWORD eprva = nt->OptionalHeader.AddressOfEntryPoint;
    printf("calling entry point (RVA 0x%x) with DLL_PROCESS_ATTACH...\n", eprva); fflush(stdout);

    /* VEH (registered in main) will report any 0xC0000005 with its faulting address,
       from any thread, so we can localize it to stage-1 / stage-2 / stage-3. */
    typedef void(WINAPI* EPFn)(HINSTANCE, DWORD, LPVOID);
    ((EPFn)((LPBYTE)base + eprva))((HINSTANCE)base, 1, NULL);
    printf("entry point returned; giving the worm a moment...\n"); fflush(stdout);

    Sleep(4000);
    DWORD s=0; GetExtendedTcpTable(NULL,&s,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);
    unsigned char* b=(unsigned char*)GlobalAlloc(GMEM_MOVEABLE,s);
    if (GetExtendedTcpTable(b,&s,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0)!=NO_ERROR){printf("tcp table fail\n");return 5;}
    MIB_TCPTABLE_OWNER_PID* t=(MIB_TCPTABLE_OWNER_PID*)b;
    int found=0;
    for (DWORD i=0;i<t->dwNumEntries;i++){
        MIB_TCPROW_OWNER_PID* r=&t->table[i];
        if (r->dwState!=2) continue;
        unsigned short port=(unsigned short)(r->dwLocalPort>>16);
        if (port>=1024 && port<=9999){ printf("  LISTENING worm port: %u (pid %lu)\n",port,r->dwOwningPid); found=1; }
    }
    GlobalFree(b);
    if (found){ printf("VERDICT: worm active - HTTP server listening (3-layer chain works)\n"); return 0; }
    printf("VERDICT: no worm listener found\n");
    return 6;
}
