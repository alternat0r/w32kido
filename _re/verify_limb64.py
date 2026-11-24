import random
random.seed(5)
mod = bytearray(open('rsa_mod.bin','rb').read())
n = int.from_bytes(mod,'big')

def to_limbs64(b128):
    v=int.from_bytes(bytes(b128),'big')
    return [(v>>(64*k)) & 0xFFFFFFFFFFFFFFFF for k in range(16)]

def limbs_to_int(R):
    v=0
    for k in range(16):
        v |= R[k] << (64*k)
    return v & ((1<<1024)-1)

def my_modmul(a,b,m):
    A=to_limbs64(a); B=to_limbs64(b); M=to_limbs64(m)
    P=[0]*33
    for i in range(16):
        for j in range(16):
            t=P[i+j]+A[i]*B[j]
            P[i+j]=t & 0xFFFFFFFFFFFFFFFF
            P[i+j+1]+= t>>64
    R=[0]*17
    for i in range(31,-1,-1):
        for bit in range(63,-1,-1):
            for k in range(16,0,-1):
                R[k]=(R[k]<<1)|(R[k-1]>>63)
            R[0]=(R[0]<<1)|((P[i]>>bit)&1)
            Rt=list(reversed(R[1:17])); Mt=[0]+list(reversed(M))
            if tuple(Rt)>=tuple(Mt):
                borrow=0
                for k in range(16):
                    v=R[k]-M[k]-borrow
                    R[k]=v & 0xFFFFFFFFFFFFFFFF
                    borrow=1 if v<0 else 0
                R[16]-=borrow
    return limbs_to_int(R).to_bytes(128,'big')

def my_modexp(base,exp,m):
    acc=(1).to_bytes(128,'big')
    top=0
    for i in range(31,-1,-1):
        if (exp>>i)&1: top=i; break
    for i in range(top,-1,-1):
        acc=my_modmul(acc,acc,m)
        if (exp>>i)&1: acc=my_modmul(acc,base,m)
    return acc

ok=True
for t in range(40):
    a=bytearray(random.getrandbits(8) for _ in range(128)); a[0]=0
    b=bytearray(random.getrandbits(8) for _ in range(128)); b[0]=0
    exp=(int.from_bytes(a,'big')*int.from_bytes(b,'big')%n).to_bytes(128,'big')
    if my_modmul(a,b,mod)!=exp: ok=False; print("modmul MISMATCH",t); break
print("modmul all correct:", ok)
ok2=True
for t in range(10):
    base=bytearray(random.getrandbits(8) for _ in range(128)); base[0]=0
    e=random.randint(1,2**40)
    exp=pow(int.from_bytes(base,'big'),e,n).to_bytes(128,'big')
    if my_modexp(base,e,mod)!=exp: ok2=False; print("modexp MISMATCH",t); break
print("modexp all correct:", ok2)
