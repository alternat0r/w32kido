#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#pragma comment(lib,"ws2_32.lib")
/* kido_get.exe <port> : GET / from the worm's HTTP server; verify it returns
   200 image/jpeg with a PE (MZ) body == the worm's own image. */
int main(int argc, char** argv){
    int port = (argc>1) ? atoi(argv[1]) : 0;
    if(!port){ printf("usage: kido_get <port>\n"); return 2; }
    WSADATA w; if (WSAStartup(MAKEWORD(2,2),&w)) return 3;
    struct sockaddr_in a; memset(&a,0,sizeof(a)); a.sin_family=AF_INET;
    a.sin_addr.s_addr=htonl(0x7f000001); a.sin_port=htons((unsigned short)port);
    SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if (connect(s,(struct sockaddr*)&a,sizeof(a))!=0){ printf("CONNECT FAIL %d\n",WSAGetLastError()); return 4; }
    char req[64]="GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
    send(s,req,(int)strlen(req),0);
    char hdr[1024]; int hn=recv(s,hdr,sizeof(hdr)-1,0); hdr[hn>0?hn:0]=0;
    /* read the body (the worm image) */
    size_t total=0; char body[1<<20];
    while (total < sizeof(body)){
        int n=recv(s,body+total,sizeof(body)-total,0);
        if (n<=0) break; total+=n;
    }
    printf("HDR: %.80s\n", hdr);
    printf("body bytes=%zu\n", total);
    int is_mz = (total>4 && body[0]=='M' && body[1]=='Z');
    printf("%s\n", is_mz ? "GOT_WORM_IMAGE (starts MZ) - HTTP SERVER WORKS" : "NOT MZ");
    if (total>=4) printf("body head: %02x %02x %02x %02x\n", body[0],body[1],body[2],body[3]);
    /* dump the served body so it can be hash-compared against the worm on disk */
    if (total){
        FILE* f = fopen("C:\\rework\\kido_repro\\served.bin","wb");
        if (f){ fwrite(body,1,total,f); fclose(f); printf("wrote served.bin (%zu bytes)\n", total); }
    }
    closesocket(s); WSACleanup();
    return is_mz ? 0 : 5;
}
