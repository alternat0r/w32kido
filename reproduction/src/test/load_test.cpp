/*====================================================================================
 *  KIDO reproduction - full-chain LoadLibrary driver (built on host, run on VM)
 *
 *  Usage:  load_test.exe <path-to-stage1.dll>
 *
 *  Loads the stage-1 reflective loader DLL. Its DllMain decodes + reflectively maps
 *  the embedded stage-2 (UPX-packed worm) and hands off to the UPX stub, which
 *  unpacks and runs the worm's DllMain -> main thread. The worm's first observable
 *  act is opening a listening TCP socket on a random port in 1024..9999. This
 *  driver loads the DLL, waits, then scans the TCP table for a listener in that
 *  range and reports it. It never calls any export - the work is all in DllMain.
 *====================================================================================*/
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#pragma comment(lib, "iphlpapi.lib")

int main(int argc, char** argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <stage1.dll>\n", argv[0]); return 2; }
    const char* path = argv[1];

    HMODULE m = LoadLibraryA(path);
    if (!m) { printf("LoadLibrary FAILED err=%lu\n", GetLastError()); return 1; }
    printf("loaded %s at 0x%p\n", path, m);
    printf("giving the worm a moment to start its HTTP server...\n");
    Sleep(4000);

    /* scan the IPv4 TCP table for a LISTENING socket in 1024..9999 */
    DWORD sz = 0;
    GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (!sz) { printf("GetExtendedTcpTable size probe failed\n"); return 3; }
    unsigned char* buf = (unsigned char*)GlobalAlloc(GMEM_MOVEABLE, sz);
    if (!buf) { printf("alloc failed\n"); return 3; }
    if (GetExtendedTcpTable(buf, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR){
        printf("GetExtendedTcpTable failed\n"); GlobalFree(buf); return 3;
    }
    MIB_TCPTABLE_OWNER_PID* t = (MIB_TCPTABLE_OWNER_PID*)buf;
    printf("tcp entries: %lu\n", t->dwNumEntries);
    int found = 0;
    for (DWORD i = 0; i < t->dwNumEntries; i++){
        MIB_TCPROW_OWNER_PID* r = &t->table[i];
        if (r->dwState != 2 /*MIB_TCP_STATE_LISTEN*/) continue;
        unsigned short port = (unsigned short)(r->dwLocalPort >> 16);
        if (port >= 1024 && port <= 9999){
            printf("  LISTENING worm port: %u  (pid %lu)\n", port, r->dwOwningPid);
            found = 1;
        }
    }
    GlobalFree(buf);
    if (found) { printf("VERDICT: worm active - HTTP server listening (3-layer chain works)\n"); return 0; }
    printf("VERDICT: no worm listener found in 1024..9999\n");
    return 4;
}
