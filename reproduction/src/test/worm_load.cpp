/*====================================================================================
 *  KIDO reproduction - direct worm loader (built on host, run on VM)
 *  Loads the STAGE-3 worm DLL (kido_worm.dll) via the real Windows PE loader
 *  (LoadLibraryA), exactly as svchost hosts the Conficker worm.  The worm's DllMain
 *  (no nested LoadLibraryA, unlike stage-1) runs: keyboard guard -> single-instance
 *  mutex -> main thread -> ... -> HTTP server on a random port 1024..9999.
 *  The driver waits, scans the TCP table for that listener, reports it, and cleans up.
 *  Usage:  worm_load.exe <kido_worm.dll>
 *====================================================================================*/
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#pragma comment(lib, "iphlpapi.lib")

int main(int argc, char** argv){
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc<2){ fprintf(stderr,"usage: %s <worm.dll>\n",argv[0]); return 2; }
    char path[MAX_PATH]; GetFullPathNameA(argv[1],MAX_PATH,path,NULL);

    HMODULE m = LoadLibraryA(path);
    if (!m){ printf("LoadLibrary FAILED err=%lu\n", GetLastError()); return 1; }
    printf("LoadLibrary OK: worm at 0x%p\n", (void*)m);
    printf("worm DllMain ran (keyboard guard + single-instance mutex + main thread)\n");

    /* The worm's first HTTP bind is delayed by a ~10s "stop SharedAccess" sleep
       (kido_bind_random_port), so give it a generous window before we scan. */
    int seen=0;
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
            if (port>=1024 && port<=9999){
                printf("  [t=%2ds] WORM HTTP LISTEN port %u (pid %lu)\n", i, port, r->dwOwningPid);
                seen=1;
            }
        }
        GlobalFree(b);
        if (seen) break;
    }
    if (seen) printf("VERDICT: worm active - HTTP server listening (stage-3 runs)\n");
    else printf("VERDICT: no worm listener (check single-instance mutex / keyboard)\n");

    /* clean up: unload the worm so its threads stop */
    FreeLibrary(m);
    printf("FreeLibrary done\n");
    return 0;
}
