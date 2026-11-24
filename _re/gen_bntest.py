import random
random.seed(11)
mod = bytearray(open('rsa_mod.bin','rb').read())
n = int.from_bytes(mod,'big')
def hex128(b): return ','.join('0x%02X'%x for x in b)
cases=[]
for t in range(4):
    a=bytearray(random.getrandbits(8) for _ in range(128)); a[0]=0
    b=bytearray(random.getrandbits(8) for _ in range(128)); b[0]=0
    exp=(int.from_bytes(a,'big')*int.from_bytes(b,'big')%n)
    cases.append((a,b,exp.to_bytes(128,'big')))

# emit the 128-bit multiply + reduction standalone (copied from crypto.cpp)
cpp = open(r'E:/projects/analysis/2026-w32kido/reproduction/src/worm/crypto.cpp').read()
import re
start = cpp.index('#define BNL')
end = cpp.index('/* D = base ^ exp')
bn_src = cpp[start:end]
bn_src = bn_src.replace('static void bn_modmul','void bn_modmul')

c = ['#include <stdio.h>','#include <stdint.h>','#include <string.h>']
c.append(bn_src)
c.append('static const uint8_t MOD[128]={%s};'%hex128(mod))
c.append('int main(void){')
c.append('puts("BUILD_VERB2");')
for t,(a,b,exp) in enumerate(cases):
    c.append('  {')
    c.append('    uint8_t A[128]={%s};'%hex128(a))
    c.append('    uint8_t B[128]={%s};'%hex128(b))
    c.append('    uint8_t E[128]={%s};'%hex128(exp))
    c.append('    uint8_t R[128]; bn_modmul(A,B,MOD,R);')
    if t==0:
        c.append('    printf("DBG case0: got=%02X%02X%02X%02X want=%02X%02X%02X%02X\\n",R[0],R[1],R[2],R[3],E[0],E[1],E[2],E[3]);')
    c.append('    int bad=-1; for(int i=0;i<128;i++){ if(R[i]!=E[i]){bad=i;break;} }')
    c.append(f'    if(bad<0) printf("case {t} : OK\\n"); else printf("case {t} : BAD diff@%d got%02X want%02X\\n", bad, R[bad], E[bad]);')
    c.append('  }')
c.append('  return 0;')
c.append('}')
open('test_bn_mul.c','w').write('\n'.join(c))
print("wrote test_bn_mul.c", len('\n'.join(c)), "bytes")
