modbytes = ((1<<64)+5).to_bytes(128,'big')
a = (3).to_bytes(128,'big')
b = (7).to_bytes(128,'big')
exp = (21).to_bytes(128,'big')
def hexarr(x): return ','.join('0x%02X'%v for v in x)

body = r'''#include <stdio.h>
#include <stdint.h>
#include <string.h>
void bn_bytes_to_limbs(const uint8_t*b,uint64_t*L){for(int k=0;k<16;k++){uint64_t v=0;for(int q=0;q<8;q++)v=(v<<8)|b[120-8*k+q];L[k]=v;}}
void bn_limbs_to_bytes(const uint64_t*L,uint8_t*o){for(int k=0;k<16;k++)for(int q=0;q<8;q++)o[120-8*k+q]=(uint8_t)(L[k]>>(8*q));}
void bn_modmul(const uint8_t*a,const uint8_t*b,const uint8_t*m,uint8_t*res){
 uint64_t A[16],B[16],M[16];bn_bytes_to_limbs(a,A);bn_bytes_to_limbs(b,B);bn_bytes_to_limbs(m,M);
 uint64_t P[34];memset(P,0,sizeof(P));
 for(int i=0;i<16;i++)for(int j=0;j<16;j++){
  uint32_t a0=(uint32_t)A[i],a1=(uint32_t)(A[i]>>32),b0=(uint32_t)B[j],b1=(uint32_t)(B[j]>>32);
  uint64_t p00=(uint64_t)a0*b0,p01=(uint64_t)a0*b1,p10=(uint64_t)a1*b0,p11=(uint64_t)a1*b1;
  uint64_t mid=(p01&0xFFFFFFFFu)+(p10&0xFFFFFFFFu)+(p00>>32);
  uint64_t hi=p11+(p01>>32)+(p10>>32)+(mid>>32);
  uint64_t lo=(p00&0xFFFFFFFFu)|(mid<<32);
  uint64_t pv=P[i+j];P[i+j]+=lo;uint64_t c1=(P[i+j]<pv)?1:0;
  pv=P[i+j+1];P[i+j+1]+=hi+c1;uint64_t c2=(P[i+j+1]<pv)?1:0;P[i+j+2]+=c2;}
 for(int i=0;i<33;i++){P[i+1]+=(P[i]>>63)&1u;P[i]&=0xFFFFFFFFFFFFFFFFull;}
 uint64_t R[18];memset(R,0,sizeof(R));
 for(int i=31;i>=0;i--)for(int bit=63;bit>=0;bit--){
  for(int k=17;k>0;k--)R[k]=((R[k]<<1)|(R[k-1]>>63))&0xFFFFFFFFFFFFFFFFull;
  R[0]=((R[0]<<1)|((P[i]>>bit)&1))&0xFFFFFFFFFFFFFFFFull;
  int cmp=0;for(int k=17;k>=0;k--){uint64_t mk=(k<16)?M[k]:0;if(R[k]>mk){cmp=1;break;}if(R[k]<mk){cmp=-1;break;}}
  if(cmp>=0){int borrow=0;for(int k=0;k<18;k++){uint64_t mi=(k<16)?M[k]:0;uint64_t prev=R[k];R[k]=prev-mi-(uint64_t)borrow;borrow=(prev<mi+(uint64_t)borrow)?1:0;}}}
 bn_limbs_to_bytes(R,res);
}
int main(void){
 const uint8_t M[128]={__MOD__};
 const uint8_t Aarr[128]={__A__};
 const uint8_t Barr[128]={__B__};
 const uint8_t Earr[128]={__E__};
 uint8_t R[128];bn_modmul(Aarr,Barr,M,R);
 int ok=1;for(int i=0;i<128;i++)if(R[i]!=Earr[i])ok=0;
 printf("small mod: %s\n", ok?"OK":"BAD");
 if(!ok) for(int i=0;i<4;i++)printf("  R=%02X E=%02X\n",R[127-i],E[127-i]);
 return 0;
}
'''
body = body.replace('__MOD__', hexarr(modbytes)).replace('__A__', hexarr(a)).replace('__B__', hexarr(b)).replace('__E__', hexarr(exp))
open('test_small.c','w').write(body)
print("wrote test_small.c", len(body))
