import random
random.seed(11)
mod = bytearray(open('rsa_mod.bin','rb').read())
n = int.from_bytes(mod,'big')
a=bytearray(random.getrandbits(8) for _ in range(128)); a[0]=0
b=bytearray(random.getrandbits(8) for _ in range(128)); b[0]=0
def hex128(x): return ','.join('0x%02X'%v for v in x)
NL='\\n'
# Build a self-contained modmul that DUMPS P (as 32 64-bit) and R
L=['#include <stdio.h>','#include <stdint.h>','#include <string.h>']
L.append('int main(void){')
L.append(' const uint8_t M[128]={' + hex128(mod) + '};')
L.append(' const uint8_t AA[128]={' + hex128(a) + '};')
L.append(' const uint8_t BB[128]={' + hex128(b) + '};')
L.append(' {')
L.append('  uint32_t A[32],B[32];')
L.append('  for(int k=0;k<32;k++){A[k]=AA[124-4*k]<<24|AA[125-4*k]<<16|AA[126-4*k]<<8|AA[127-4*k];B[k]=BB[124-4*k]<<24|BB[125-4*k]<<16|BB[126-4*k]<<8|BB[127-4*k];}')
L.append('  uint64_t P[68];memset(P,0,sizeof(P));')
L.append('  for(int i=0;i<32;i++)for(int j=0;j<32;j++){uint64_t acc=P[i+j]+(uint64_t)A[i]*B[j];P[i+j]=acc&0xFFFFFFFFu;uint64_t carry=acc>>32;int idx=i+j+1;while(carry){uint64_t s=P[idx]+carry;P[idx]=s&0xFFFFFFFFu;carry=s>>32;idx++;}}')
L.append('  for(int k=32;k>=0;k--){uint64_t p64=P[2*k]|(P[2*k+1]<<32);printf("P64_%d=%016llX' + NL + '",k,(unsigned long long)p64);}')
L.append('  uint64_t M64[16];for(int k=0;k<16;k++){uint64_t v=0;for(int q=0;q<8;q++)v=(v<<8)|M[120-8*k+q];M64[k]=v;}')
L.append('  uint64_t R[18];memset(R,0,sizeof(R));')
L.append('  for(int i=63;i>=0;i--){uint32_t limb=(uint32_t)P[i];for(int bit=31;bit>=0;bit--){for(int k=17;k>0;k--)R[k]=((R[k]<<1)|(R[k-1]>>63))&0xFFFFFFFFFFFFFFFFull;R[0]=((R[0]<<1)|((limb>>bit)&1))&0xFFFFFFFFFFFFFFFFull;int cmp=0;for(int k=17;k>=0;k--){uint64_t mk=(k<16)?M64[k]:0;if(R[k]>mk){cmp=1;break;}if(R[k]<mk){cmp=-1;break;}}if(cmp>=0){int borrow=0;for(int k=0;k<18;k++){uint64_t mi=(k<16)?M64[k]:0;uint64_t prev=R[k];R[k]=prev-mi-(uint64_t)borrow;borrow=(prev<mi+(uint64_t)borrow)?1:0;}}}}')
L.append('  for(int k=17;k>=0;k--)printf("R%d=%016llX' + NL + '",k,(unsigned long long)R[k]);')
L.append(' }')
L.append(' return 0;}')
open('test_dbg.c','w').write('\n'.join(L))
# python reference
prod=int.from_bytes(a,'big')*int.from_bytes(b,'big')
P64=[(prod>>(64*k))&0xFFFFFFFFFFFFFFFF for k in range(33)]
open('py_p64.txt','w').write('\n'.join("P64_%d=%016X"%(k,v) for k,v in reversed(list(enumerate(P64)))))
# python R
M64=[(n>>(64*k))&0xFFFFFFFFFFFFFFFF for k in range(16)]
R=[0]*18
P32=[(prod>>(32*k))&0xFFFFFFFF for k in range(64)]
for i in range(63,-1,-1):
    limb=P32[i]
    for bit in range(31,-1,-1):
        for k in range(17,0,-1): R[k]=((R[k]<<1)|(R[k-1]>>63))&0xFFFFFFFFFFFFFFFF
        R[0]=((R[0]<<1)|((limb>>bit)&1))&0xFFFFFFFFFFFFFFFF
        cmp=0
        for k in range(17,-1,-1):
            mk=M64[k] if k<16 else 0
            if R[k]>mk: cmp=1;break
            if R[k]<mk: cmp=-1;break
        if cmp>=0:
            borrow=0
            for k in range(18):
                mi=M64[k] if k<16 else 0
                prev=R[k]; R[k]=(prev-mi-borrow)&0xFFFFFFFFFFFFFFFF; borrow=1 if prev<mi+borrow else 0
open('py_R.txt','w').write('\n'.join("R%d=%016X"%(k,R[k]) for k in range(17,-1,-1)))
print("wrote test_dbg.c; P64[0]=",hex(P64[0]),"R0=",hex(R[0]))
