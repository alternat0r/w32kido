import random
random.seed(11)
a=bytearray(random.getrandbits(8) for _ in range(128)); a[0]=0
b=bytearray(random.getrandbits(8) for _ in range(128)); b[0]=0
def hex128(x): return ','.join('0x%02X'%v for v in x)
NL = '\\n'  # literal backslash-n for C
lines=[]
lines.append('#include <stdio.h>')
lines.append('#include <stdint.h>')
lines.append('#include <string.h>')
lines.append('void to_l(const uint8_t*b,uint64_t*L){for(int k=0;k<16;k++){uint64_t v=0;for(int q=0;q<8;q++)v=(v<<8)|b[120-8*k+q];L[k]=v;}}')
lines.append('int main(void){')
lines.append(' const uint8_t AA[128]={' + hex128(a) + '};')
lines.append(' const uint8_t BB[128]={' + hex128(b) + '};')
lines.append(' uint64_t A[16],B[16];to_l(AA,A);to_l(BB,B);')
lines.append(' uint64_t P[34];memset(P,0,sizeof(P));')
lines.append(' for(int i=0;i<16;i++)for(int j=0;j<16;j++){')
lines.append('  unsigned __int128 pp=(unsigned __int128)A[i]*(unsigned __int128)B[j];')
lines.append('  uint64_t lo=(uint64_t)pp, hi=(uint64_t)(pp>>64);')
lines.append('  { uint64_t lo_s=lo+P[i+j]; uint64_t c1=(lo_s<lo)?1:0; uint64_t hi_s=hi+c1; uint64_t c2=(hi_s<hi)?1:0; P[i+j]=lo_s; P[i+j+1]+=hi_s; P[i+j+2]+=c2; }')
lines.append(' }')
lines.append(' for(int i=0;i<33;i++){P[i+1]+=(P[i]>>63)&1u;P[i]&=0xFFFFFFFFFFFFFFFFull;}')
lines.append(' for(int k=33;k>=0;k--)printf("P%d=%016llX' + NL + '",k,(unsigned long long)P[k]);')
lines.append(' return 0;}')
open('test_prod33.c','w').write('\n'.join(lines))
print("wrote test_prod33.c")
print("printf line:", lines[-2])
