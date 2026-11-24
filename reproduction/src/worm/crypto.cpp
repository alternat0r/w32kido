/*====================================================================================
 *  KIDO worm - crypto primitives (SHA-1, RC4, RSA-1024 verify, zlib CRC-32).
 *  Reimplemented in C++ (VS2022). SHA-1 and RC4 are standard; the RSA verify and the
 *  PKCS#1/RC4 payload gate follow kido_program_flow_pseudocode.txt section 3.10 exactly:
 *     sig block (last 128 bytes of a downloaded payload):
 *        D = sig ^ e mod n          (n = g_rsa_mod, e = 0xC351 = 50001)
 *        require D[0x00..0x58) == 00 01 FF..FF   (PKCS#1 v1.5 type-1, 86 x 0xFF)
 *        key   = D[0x58..0x6C)                     (20-byte RC4 key, inside signed block)
 *        require D[0x6C..0x80) == SHA1(ENCRYPTED body)
 *        RC4_decrypt_in_place(body, key)
 *        require SHA1(decrypted body) == key
 *  Only the holder of the private key can make a payload that passes.
 *====================================================================================*/
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ----------------------------- SHA-1 ----------------------------- */
typedef struct { uint32_t h[5]; uint64_t total; uint8_t buf[64]; uint32_t buflen; } SHA1_CTX;

static uint32_t rol(uint32_t v, int n){ return (v<<n)|(v>>(32-n)); }

void sha1_init(SHA1_CTX* c)
{
    c->h[0]=0x67452301; c->h[1]=0xEFCDAB89; c->h[2]=0x98BADCFE;
    c->h[3]=0x10325476; c->h[4]=0xC3D2E1F0;
    c->total=0; c->buflen=0;
}

static void sha1_block(SHA1_CTX* c, const uint8_t* p)
{
    uint32_t w[80];
    for (int i=0;i<16;i++)
        w[i]=(p[i*4]<<24)|(p[i*4+1]<<16)|(p[i*4+2]<<8)|p[i*4+3];
    for (int i=16;i<80;i++) w[i]=rol(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
    uint32_t a=c->h[0],b=c->h[1],cc=c->h[2],d=c->h[3],e=c->h[4];
    for (int i=0;i<80;i++){
        uint32_t f,k;
        if      (i<20){ f=(b&cc)|((~b)&d); k=0x5A827999; }
        else if (i<40){ f=b^cc^d;           k=0x6ED9EBA1; }
        else if (i<60){ f=(b&cc)|(b&d)|(cc&d); k=0x8F1BBCDC; }
        else          { f=b^cc^d;           k=0xCA62C1D6; }
        uint32_t tmp=rol(a,5)+f+e+k+w[i];
        e=d; d=cc; cc=rol(b,30); b=a; a=tmp;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d; c->h[4]+=e;
}

void sha1_update(SHA1_CTX* c, const void* data, size_t len)
{
    const uint8_t* p=(const uint8_t*)data;
    c->total+=len;
    while (len){
        size_t take = 64 - c->buflen; if (take>len) take=len;
        memcpy(c->buf+c->buflen,p,take); c->buflen+=take; p+=take; len-=take;
        if (c->buflen==64){ sha1_block(c,c->buf); c->buflen=0; }
    }
}

void sha1_final(SHA1_CTX* c, uint8_t out[20])
{
    uint64_t bits = c->total*8;
    uint8_t pad=0x80; sha1_update(c,&pad,1);
    uint8_t z=0; while (c->buflen!=56) sha1_update(c,&z,1);
    uint8_t lenb[8];
    for (int i=0;i<8;i++) lenb[i]=(uint8_t)(bits>>((7-i)*8));
    sha1_update(c,lenb,8);
    for (int i=0;i<5;i++){
        out[i*4]=c->h[i]>>24; out[i*4+1]=c->h[i]>>16; out[i*4+2]=c->h[i]>>8; out[i*4+3]=c->h[i];
    }
}

/* convenience: SHA1 of a buffer -> 20 bytes (sub_09BA7) */
void sha1(const void* data, size_t len, uint8_t out[20])
{
    SHA1_CTX c; sha1_init(&c); sha1_update(&c,data,len); sha1_final(&c,out);
}

/* ----------------------------- RC4 ----------------------------- */
static void rc4_key(uint8_t S[256], const uint8_t* key, size_t keylen) /* sub_09AC3 */
{
    for (int i=0;i<256;i++) S[i]=(uint8_t)i;
    int j=0;
    for (int i=0;i<256;i++){
        j=(j+S[i]+key[i%keylen])&0xFF;
        uint8_t t=S[i]; S[i]=S[j]; S[j]=t;
    }
}
static void rc4_xfer(uint8_t S[256], int i, int j, uint8_t* buf, size_t len) /* sub_09B20 */
{
    for (size_t k=0;k<len;k++){
        i=(i+1)&0xFF;
        j=(j+S[i])&0xFF;
        uint8_t t=S[i]; S[i]=S[j]; S[j]=t;
        buf[k]^=S[(S[i]+S[j])&0xFF];
    }
}
/* RC4 crypt (in place) = key schedule + keystream xor (sub_09B75) */
void rc4_crypt(uint8_t* buf, size_t len, const uint8_t* key, size_t keylen)
{
    uint8_t S[256]; int i=0,j=0;
    rc4_key(S,key,keylen);
    rc4_xfer(S,i,j,buf,len);
}

/* ------------------------ big numbers (128-byte, big-endian) ------------------------
 *  Public API is byte-oriented (128-byte big-endian), matching the worm's layout.
 *  Internally: a 2048-bit product computed with 32-bit limbs (well-defined shifts),
 *  then a left-to-right shift-and-subtract reduction (remainder in 16x 64-bit limbs).
 *  Verified against Python's pow on the real 1024-bit modulus. */
typedef uint8_t BN128[128];   /* big-endian */

#define BNL  16   /* 16x 64-bit limbs per 1024-bit number */
#define PLIMBS 68 /* 2048-bit product in 32-bit limbs */

/* res = (a*b) mod m, all 128-byte big-endian */
static void bn_modmul(const uint8_t*a,const uint8_t*b,const uint8_t*m,uint8_t*res)
{
    /* 32-bit limbs (little-endian) of a and b.  The 128-byte array is big-endian,
       so limb k occupies bytes [124-4k .. 127-4k], byte 124-4k being that limb's MSB. */
    uint32_t A[32], B[32];
    for (int k=0;k<32;k++){
        A[k]= (uint32_t)a[124-4*k]<<24 | (uint32_t)a[125-4*k]<<16 | (uint32_t)a[126-4*k]<<8 | (uint32_t)a[127-4*k];
        B[k]= (uint32_t)b[124-4*k]<<24 | (uint32_t)b[125-4*k]<<16 | (uint32_t)b[126-4*k]<<8 | (uint32_t)b[127-4*k];
    }

    /* 2048-bit product P (32-bit limbs, little-endian) with full carry cascade */
    uint64_t P[PLIMBS]; memset(P,0,sizeof(P));
    for (int i=0;i<32;i++)
        for (int j=0;j<32;j++){
            uint64_t acc = P[i+j] + (uint64_t)A[i]*B[j];
            P[i+j] = acc & 0xFFFFFFFFu;
            uint64_t carry = acc >> 32;
            int idx = i+j+1;
            while (carry){
                uint64_t s = P[idx] + carry;
                P[idx] = s & 0xFFFFFFFFu;
                carry = s >> 32;
                idx++;
            }
        }

    /* 16x 64-bit limbs of m for the reduction */
    uint64_t M[BNL];
    for (int k=0;k<BNL;k++){
        uint64_t v=0;
        for (int b2=0;b2<8;b2++) v=(v<<8) | m[120-8*k+b2];
        M[k]=v;
    }

    /* left-to-right shift-and-subtract: R < m invariant. Feed the 2048 bits
       of P (32-bit limbs, MSB first) into a 16-limb (18-wide) running remainder. */
    uint64_t R[18]; memset(R,0,sizeof(R));
    for (int i=63;i>=0;i--){                 /* 32-bit product limbs, MSB first */
        uint32_t limb = (uint32_t)P[i];
        for (int bit=31;bit>=0;bit--){
            for (int k=17;k>0;k--)
                R[k]=((R[k]<<1)|(R[k-1]>>63)) & 0xFFFFFFFFFFFFFFFFull;
            R[0]=((R[0]<<1)|((limb>>bit)&1)) & 0xFFFFFFFFFFFFFFFFull;
            int cmp=0;
            for (int k=17;k>=0;k--){
                uint64_t mk=(k<BNL)?M[k]:0;
                if (R[k]>mk){ cmp=1; break; }
                if (R[k]<mk){ cmp=-1; break; }
            }
            if (cmp>=0){
                int borrow=0;
                for (int k=0;k<18;k++){
                    uint64_t mi=(k<BNL)?M[k]:0;
                    uint64_t prev=R[k];
                    R[k]=prev-mi-(uint64_t)borrow;
                    borrow=(prev < mi+(uint64_t)borrow) ? 1 : 0;
                }
            }
        }
    }
    for (int k=0;k<BNL;k++){
        for (int b2=0;b2<8;b2++) res[120-8*k+b2]=(uint8_t)(R[k]>>(8*(7-b2)));
    }
}

/* D = base ^ exp mod mod.  exp is a small uint32 (public exponent 0xC351 = 16 bits). */
static void bn_modexp(const uint8_t*base,uint32_t exp,const uint8_t*mod,uint8_t*res)
{
    uint8_t acc[128];
    memset(acc,0,128); acc[127]=1;      /* acc = 1 */
    int top=0; for (int i=31;i>=0;i--) if ((exp>>i)&1){ top=i; break; }
    for (int i=top;i>=0;i--){
        bn_modmul(acc,acc,mod,acc);      /* square */
        if ((exp>>i)&1) bn_modmul(acc,base,mod,acc);
    }
    memcpy(res,acc,128);
}

/* ------------------------ payload signature gate (sub_09E56) ------------------------ */
#include "kido_data.h"   /* g_rsa_mod[128], G_RSA_EXP */

/* non-RSA part of the gate: given the recovered D block, check padding + hashes
 * and RC4-decrypt the body in place.  Returns 1 on success. */
static int kido_gate_body(const uint8_t* D, uint8_t* body, size_t len)
{
    uint8_t h1[20]; sha1(body,len,h1);
    if (D[0]!=0x00 || D[1]!=0x01) return 0;
    for (int i=2;i<0x58;i++) if (D[i]!=0xFF) return 0;
    if (memcmp(D+0x6C,h1,20)!=0) return 0;
    uint8_t key[20]; memcpy(key,D+0x58,20);
    rc4_crypt(body,len,key,20);
    uint8_t h2[20]; sha1(body,len,h2);
    return memcmp(h2,key,20)==0;
}

/* verify sig(128) over body(len). On success, body is RC4-decrypted IN PLACE.
 *  D = sig^e mod n; the body must decrypt cleanly under the key carried in D. */
int kido_verify_signed(const uint8_t* sig, uint8_t* body, size_t len)
{
    if (len <= 0x80) return 0;
    uint8_t D[128];
    bn_modexp(sig,G_RSA_EXP,g_rsa_mod,D);
    return kido_gate_body(D, body, len);
}

/* ------------------------ zlib CRC-32 (sub_0D46B, dynamic table sub_0D116) ------------------------ */
static uint32_t crc_table[256];
static int crc_table_ready=0;
static void make_crc_table(void)
{
    for (uint32_t n=0;n<256;n++){
        uint32_t c=n;
        for (int k=0;k<8;k++) c=(c&1)?(0xEDB88320u^(c>>1)):(c>>1);
        crc_table[n]=c;
    }
    crc_table_ready=1;
}
uint32_t kido_crc32(const void* buf,size_t len)
{
    if (!crc_table_ready) make_crc_table();
    const uint8_t*p=(const uint8_t*)buf;
    uint32_t c=0xFFFFFFFFu;
    for (size_t i=0;i<len;i++) c=crc_table[(c^p[i])&0xFF]^(c>>8);
    return c^0xFFFFFFFFu;
}

/* test-only thin wrapper around the bignum modexp */
void kido_test_bn_modexp(const uint8_t*base,uint32_t exp,const uint8_t*mod,uint8_t*res)
{
    bn_modexp(base,exp,mod,res);
}
void kido_test_bn_modmul(const uint8_t*a,const uint8_t*b,const uint8_t*m,uint8_t*res)
{
    bn_modmul(a,b,m,res);
}

/* test-only: recover D = sig^e mod n (e = G_RSA_EXP) */
void kido_test_bn_recovD(const uint8_t*sig,uint8_t D[128])
{
    bn_modexp(sig,G_RSA_EXP,g_rsa_mod,D);
}

/* test-only: the non-RSA part of the payload gate (delegates to kido_gate_body). */
int kido_test_gate_body(const uint8_t* D, uint8_t* body, size_t len)
{
    return kido_gate_body(D, body, len);
}
