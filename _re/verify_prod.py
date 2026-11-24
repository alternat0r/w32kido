import random
random.seed(7)
mod = bytearray(open('rsa_mod.bin','rb').read())
n = int.from_bytes(mod,'big')

def prod_only(a,b):
    a=list(a); b=list(b)
    prod=[0]*256
    for i in range(127,-1,-1):
        carry=0
        for j in range(127,-1,-1):
            cur=prod[i+1+j]+a[i]*b[j]+carry
            prod[i+1+j]=cur&0xFF; carry=cur>>8
        cur=prod[i]+carry; prod[i]=cur&0xFF; carry=cur>>8
        if carry and i>0:
            cur=prod[i-1]+carry; prod[i-1]=cur&0xFF
    return bytes(prod)

ok=True
for t in range(50):
    a=bytearray(random.getrandbits(8) for _ in range(128)); a[0]=0
    b=bytearray(random.getrandbits(8) for _ in range(128)); b[0]=0
    exp=(int.from_bytes(a,'big')*int.from_bytes(b,'big')).to_bytes(256,'big')
    got=prod_only(a,b)
    if got!=exp:
        ok=False; print("PROD mismatch case",t)
        for j in range(256):
            if got[j]!=exp[j]:
                print("  first diff at prod byte",j,"got",got[j],"exp",exp[j]); break
        break
print("product correct:", ok)
