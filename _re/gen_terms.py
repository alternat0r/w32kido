import random
random.seed(11)
a=bytearray(random.getrandbits(8) for _ in range(128)); a[0]=0
b=bytearray(random.getrandbits(8) for _ in range(128)); b[0]=0
def hex128(x): return ','.join('0x%02X'%v for v in x)
NL='\\n'
L=['#include <stdio.h>','#include <stdint.h>','#include <string.h>']
L.append('int main(void){')
L.append(' const uint8_t AA[128]={' + hex128(a) + '};')
L.append(' const uint8_t BB[128]={' + hex128(b) + '};')
L.append(' uint32_t A[32],B[32];')
L.append(' for(int k=0;k<32;k++){A[k]=AA[124+4*k]<<24|AA[125+4*k]<<16|AA[126+4*k]<<8|AA[127+4*k];B[k]=BB[124+4*k]<<24|BB[125+4*k]<<16|BB[126+4*k]<<8|BB[127+4*k];}')
L.append(' printf("A1=%08X B1=%08X A0=%08X B0=%08X' + NL + '",A[1],B[1],A[0],B[0]);')
L.append(' uint64_t t01=(uint64_t)A[0]*B[1]; printf("A0*B1=%016llX' + NL + '",(unsigned long long)t01);')
L.append(' uint64_t t10=(uint64_t)A[1]*B[0]; printf("A1*B0=%016llX' + NL + '",(unsigned long long)t10);')
L.append(' return 0;}')
open('test_terms.c','w').write('\n'.join(L))
# python reference
A=[(int.from_bytes(a,'big')>>(32*k))&0xFFFFFFFF for k in range(2)]
B=[(int.from_bytes(b,'big')>>(32*k))&0xFFFFFFFF for k in range(2)]
print("PY A0*B1=%016X A1*B0=%016X"%((A[0]*B[1]),(A[1]*B[0])))
