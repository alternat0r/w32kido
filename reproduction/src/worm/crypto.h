#ifndef KIDO_CRYPTO_H
#define KIDO_CRYPTO_H
#include <stdint.h>
#include <stddef.h>

void sha1_init(void*);          /* internal; sha1() below is the API used */
void sha1(const void* data, size_t len, uint8_t out[20]);
void rc4_crypt(uint8_t* buf, size_t len, const uint8_t* key, size_t keylen);
int  kido_verify_signed(const uint8_t* sig, uint8_t* body, size_t len);
uint32_t kido_crc32(const void* buf, size_t len);

/* exposed for the self-test harness (normally file-local) */
void kido_test_bn_modexp(const uint8_t*base,uint32_t exp,const uint8_t*mod,uint8_t*res);
void kido_test_bn_modmul(const uint8_t*a,const uint8_t*b,const uint8_t*m,uint8_t*res);
void kido_test_bn_recovD(const uint8_t*sig,uint8_t D[128]);
int  kido_test_gate_body(const uint8_t*D, uint8_t*body, size_t len);

#endif
