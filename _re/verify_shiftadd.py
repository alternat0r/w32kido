import random
random.seed(5)
mod = bytearray(open('rsa_mod.bin','rb').read())
n = int.from_bytes(mod,'big')
B = 1<<32

def limbs_of(b128):
    L=[0]*4
    for i in range(4):
        L[i]= b128[127-4*i] | b128[126-4*i]<<8 | b128[125-4*i]<<16 | b128[124-4*i]<<24
    return L

def my_modmul(a,b,m):
    A=limbs_of(a); B4=limbs_of(b); M=limbs_of(m)
    P=[0]*8
    for i in range(4):
        for j in range(4):
            P[i+j]+=A[i]*B4[j]
    for i in range(7):
        P[i+1]+=P[i]>>32; P[i]&=B-1
    # left-to-right modular reduction (m as python int)
    Mv=int.from_bytes(bytes(m),'big')
    rem=0
    for i in range(7,-1,-1):
        limb=P[i]
        for bit in range(31,-1,-1):
            rem=(rem<<1)|((limb>>bit)&1)
            if rem>=Mv: rem-=Mv
    return (rem).to_bytes(128,'big')

def my_modexp(base,exp,m):
    acc=bytearray(128); acc[127]=1
    top=0
    for i in range(31,-1,-1):
        if (exp>>i)&1: top=i; break
    for i in range(top,-1,-1):
        acc=my_modmul(bytes(acc),bytes(acc),m)
        if (exp>>i)&1: acc=my_modmul(bytes(acc),base,m)
    return bytes(acc)

ok=True
for t in range(40):
    a=bytearray(random.getrandbits(8) for _ in range(128)); a[0]=0
    b=bytearray(random.getrandbits(8) for _ in range(128)); b[0]=0
    exp=(int.from_bytes(a,'big')*int.from_bytes(b,'big')%n).to_bytes(128,'big')
    got=my_modmul(a,b,mod)
    if bytes(got)!=exp:
        ok=False; print("modmul MISMATCH case",t); break
print("modmul all correct:", ok)
ok2=True
for t in range(10):
    base=bytearray(random.getrandbits(8) for _ in range(128)); base[0]=0
    e=random.randint(1,2**40)
    exp=pow(int.from_bytes(base,'big'),e,n).to_bytes(128,'big')
    got=my_modexp(bytes(base),e,mod)
    if bytes(got)!=exp:
        ok2=False; print("modexp MISMATCH case",t); break
print("modexp all correct:", ok2)
