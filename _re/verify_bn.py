import random
random.seed(7)
mod = bytearray(open('rsa_mod.bin','rb').read())
n = int.from_bytes(mod,'big')

def c_modmul(a,b,mbytes):
    a=list(a); b=list(b); m=list(mbytes)
    prod=[0]*256
    for i in range(127,-1,-1):
        carry=0
        for j in range(127,-1,-1):
            cur=prod[i+1+j]+a[i]*b[j]+carry
            prod[i+1+j]=cur&0xFF; carry=cur>>8
        cur=prod[i]+carry; prod[i]=cur&0xFF; carry=cur>>8
        if carry and i>0:
            cur=prod[i-1]+carry; prod[i-1]=cur&0xFF
    rem=[0]*256
    for i in range(256):
        for j in range(255,0,-1): rem[j]=rem[j-1]
        rem[0]=prod[i]
        while True:
            top128=bytes(rem[128:256])
            if int.from_bytes(top128,'big') < n: break
            borrow=0
            for j in range(255,127,-1):
                dd=rem[j]-m[j-128]-borrow
                rem[j]=dd&0xFF; borrow=1 if dd<0 else 0
    return bytes(rem[128:256])

def c_modexp(base, expbytes, ebits, mbytes):
    acc=bytearray(128); acc[127]=1
    for i in range(ebits):
        bytei=(i+7)//8
        bit=(expbytes[bytei]>>(7-(i%8)))&1
        acc=c_modmul(acc,acc,mbytes)
        if bit: acc=c_modmul(acc,base,mbytes)
    return bytes(acc)

ok=True
for t in range(30):
    a=bytearray(random.getrandbits(8) for _ in range(128)); a[0]=0
    b=bytearray(random.getrandbits(8) for _ in range(128)); b[0]=0
    exp=(int.from_bytes(a,'big')*int.from_bytes(b,'big')%n).to_bytes(128,'big')
    got=c_modmul(a,b,mod)
    if got!=exp:
        ok=False; print("modmul MISMATCH case",t)
        for j in range(128):
            if got[j]!=exp[j]: print("  first diff at byte",j,"got",got[j],"exp",exp[j]); break
        break
print("modmul all correct:", ok)

ok2=True
for t in range(30):
    base=bytearray(random.getrandbits(8) for _ in range(128)); base[0]=0
    e=random.randint(1,2**40)
    eb=e.to_bytes(128,'big')
    exp=pow(int.from_bytes(base,'big'), e, n).to_bytes(128,'big')
    got=c_modexp(base, eb, 1024, mod)
    if got!=exp:
        ok2=False; print("modexp MISMATCH case",t)
        for j in range(128):
            if got[j]!=exp[j]: print("  first diff at byte",j); break
        break
print("modexp all correct:", ok2)
