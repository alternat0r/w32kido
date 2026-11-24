/*====================================================================================
 *  Standalone self-test for the worm's crypto primitives.  A console app (NO network,
 *  NO service, NO registry side effects) so it can be executed safely on the analysis VM
 *  to prove the reimplementation is correct.  Built with the same MSVC 2022 toolchain.
 *====================================================================================*/
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "crypto.h"
#include "kido_data.h"

static int fails = 0;
#define CHECK(cond, msg) do{ if(cond){printf("PASS  %s\n",msg);} else {printf("FAIL  %s\n",msg); fails++;} }while(0)

static void hex(const uint8_t*p,int n,char*o){ for(int i=0;i<n;i++) sprintf(o+i*2,"%02x",p[i]); o[2*n]=0; }

int main(void)
{
    /* 1. SHA-1 known answer (FIPS 180-2 / NIST): SHA1("abc") */
    {
        uint8_t out[20]; sha1("abc",3,out);
        char h[41]; hex(out,20,h);
        CHECK(strcmp(h,"a9993e364706816aba3e25717850c26c9cd0d89d")==0, "SHA1(\"abc\")");
    }
    {
        uint8_t out[20]; const char*s="abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        sha1(s,strlen(s),out); char h[41]; hex(out,20,h);
        CHECK(strcmp(h,"84983e441c3bd26ebaae4aa1f95129e5e54670f1")==0, "SHA1 56-byte message");
    }
    /* 2. RC4 (RFC 6229): key "Key", data "Plaintext" -> BBF316E8D940AF0AD3 */
    {
        uint8_t d[]="Plaintext"; rc4_crypt(d,9,(const uint8_t*)"Key",3);
        char h[19]; hex(d,9,h);
        CHECK(stricmp(h,"bbf316e8d940af0ad3")==0, "RC4 RFC6229");
    }
    /* 3. CRC-32 (zlib/PE): "123456789" -> CBF43926 */
    {
        uint32_t c=kido_crc32("123456789",9);
        CHECK(c==0xCBF43926u, "CRC32(\"123456789\")");
    }
    /* 4. bignum modexp vs self-consistency: g^4 == g^3 * g mod m */
    {
        uint8_t g[128], e1[128], resA[128], resB[128];
        for(int i=0;i<128;i++) g[i]=(uint8_t)(i*7+3); g[0]=g[1]=g[2]=g[3]=0;
        kido_test_bn_modexp(g,3,g_rsa_mod,e1);   /* g^3 */
        kido_test_bn_modmul(e1,g,g_rsa_mod,resA); /* g^3 * g */
        kido_test_bn_modexp(g,4,g_rsa_mod,resB);  /* g^4 */
        CHECK(memcmp(resA,resB,128)==0, "bignum g^4 == g^3*g (mod m)");
        (void)e1;
    }
    /* 5. RSA public op: D = sig^e mod n  (compared against Python's pow on a fixed sig).
       The worm only does the public exponentiation (e=0xC351); the private d that
       produced sig is unknown to it.  This pins bn_modexp to the real modulus. */
    {
        static const uint8_t SIG[128]={
          0x00, 0x03, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7A, 0x8B, 0x9C, 0xAD, 0xBE, 0xCF, 0xE0, 0xF1,
          0x02, 0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8A, 0x9B, 0xAC, 0xBD, 0xCE, 0xDF, 0xF0, 0x01,
          0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9A, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0x00, 0x11,
          0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x21,
          0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F, 0x20, 0x31,
          0x42, 0x53, 0x64, 0x75, 0x86, 0x97, 0xA8, 0xB9, 0xCA, 0xDB, 0xEC, 0xFD, 0x0E, 0x1F, 0x30, 0x41,
          0x52, 0x63, 0x74, 0x85, 0x96, 0xA7, 0xB8, 0xC9, 0xDA, 0xEB, 0xFC, 0x0D, 0x1E, 0x2F, 0x40, 0x51,
          0x62, 0x73, 0x84, 0x95, 0xA6, 0xB7, 0xC8, 0xD9, 0xEA, 0xFB, 0x0C, 0x1D, 0x2E, 0x3F, 0x50, 0x61};
        static const uint8_t WANT[128]={
          0x05,0x1b,0xc4,0xa0,0xcf,0xd0,0x72,0x7d,0x68,0x0a,0xf1,0x9a,0x03,0x32,0xd2,0x8b,
          0x93,0x86,0xa9,0x7a,0xd1,0xbb,0x0e,0xdb,0x39,0xbf,0x9b,0xbd,0xed,0x1a,0x63,0x91,
          0x87,0x30,0x49,0x8d,0x70,0xc4,0xec,0xac,0x8f,0x69,0xe5,0x83,0xad,0xe5,0xed,0x56,
          0x1f,0xa2,0xe4,0x86,0xaa,0x74,0x36,0x3f,0xd5,0x0a,0x25,0xbe,0xad,0x9d,0x8b,0x3e,
          0x9a,0x10,0x38,0x9b,0xeb,0xbc,0xc8,0xc1,0x03,0xf6,0x64,0xc6,0xee,0x4b,0xae,0xb3,
          0x8c,0x72,0x75,0xff,0xc3,0x8f,0xa6,0x24,0xac,0xd2,0xe4,0x50,0xbb,0xfa,0x66,0x71,
          0x58,0x72,0xaf,0x53,0x9c,0xd7,0xda,0xb3,0x45,0xb5,0xd7,0xae,0x8e,0x6e,0x85,0x3f,
          0x31,0x5e,0xbb,0x11,0x5e,0x84,0xf8,0x0b,0xb4,0x41,0x2f,0xcc,0x8a,0xaa,0xfd,0x6e};
        uint8_t D[128]; kido_test_bn_recovD(SIG,D);
        CHECK(memcmp(D,WANT,128)==0, "RSA public op sig^e mod n == Python pow");
    }
    /* 6. Payload-signature gate: structure + RC4 (independent of RSA).
       Precompute a D that the gate must accept, then feed it through a helper that
       checks padding + hash + RC4-decrypt + final-hash (the non-RSA part of the gate). */
    {
        const int L=256;
        static uint8_t B[L], E[L];
        srand(12345); for(int i=0;i<L;i++) B[i]=(uint8_t)rand();
        uint8_t K[20]; sha1(B,L,K);            /* K must equal SHA1(decrypted body) */
        memcpy(E,B,L); rc4_crypt(E,L,K,20);     /* E = encrypted body */
        uint8_t h1[20]; sha1(E,L,h1);           /* hash of ENCRYPTED body */
        uint8_t D[128]; memset(D,0,128);
        D[0]=0x00; D[1]=0x01;
        for(int i=2;i<0x58;i++) D[i]=0xFF;      /* 86 x 0xFF */
        memcpy(D+0x58,K,20);                    /* RC4 key */
        memcpy(D+0x6C,h1,20);                   /* SHA1(encrypted) */
        /* gate-structure check: given D, the body E must decrypt to B */
        extern int kido_test_gate_body(const uint8_t*D, uint8_t*body, size_t len);
        uint8_t got[L]; memcpy(got,E,L);
        CHECK(kido_test_gate_body(D,got,L)==1, "gate accepts correct D + decrypts body");
        CHECK(memcmp(got,B,L)==0, "gate RC4-decrypts body to original");
        /* negative: corrupt a padding byte -> reject */
        uint8_t Dbad[128]; memcpy(Dbad,D,128); Dbad[10]^=0x10;
        uint8_t got2[L]; memcpy(got2,E,L);
        CHECK(kido_test_gate_body(Dbad,got2,L)==0, "gate rejects bad padding");
        /* negative: corrupt body -> reject */
        uint8_t bad[L]; memcpy(bad,E,L); bad[5]^=0x10;
        CHECK(kido_test_gate_body(D,bad,L)==0, "gate rejects corrupted body");
    }
    printf("\n%d failure(s)\n", fails);
    return fails?1:0;
}
