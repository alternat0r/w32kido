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
L.append(' for(int k=0;k<32;k++){A[k]=AA[124-4*k]<<24|AA[125-4*k]<<16|AA[126-4*k]<<8|AA[127-4*k];B[k]=BB[124-4*k]<<24|BB[125-4*k]<<16|BB[126-4*k]<<8|BB[127-4*k];}')
L.append(' uint64_t P[68];memset(P,0,sizeof(P));')
L.append(' for(int i=0;i<32;i++)for(int j=0;j<32;j++){')
L.append('  uint64_t acc=P[i+j]+(uint64_t)A[i]*B[j];P[i+j]=acc&0xFFFFFFFFu;uint64_t carry=acc>>32;int idx=i+j+1;')
L.append('  while(carry){uint64_t s=P[idx]+carry;P[idx]=s&0xFFFFFFFFu;carry=s>>32;idx++;}')
L.append(' }')
L.append(' for(int k=63;k>=0;k--)printf("P%d=%08llX' + NL + '",k,(unsigned long long)P[k]);')
L.append(' return 0;}')
open('test_p32.c','w').write('\n'.join(L))
prod=int.from_bytes(a,'big')*int.from_bytes(b,'big')
Ppy=[(prod>>(32*k))&0xFFFFFFFF for k in range(64)]
open('py_p32.txt','w').write('\n'.join("P%d=%08X"%(k,v) for k,v in reversed(list(enumerate(Ppy)))))
print("wrote test_p32.c (corrected A/B); P0 expect", hex(Ppy[0]))
