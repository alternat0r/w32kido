import random
random.seed(3)
mod = bytearray(open('rsa_mod.bin','rb').read())
n = int.from_bytes(mod,'big')

def bytes_to_limbs4(b):
    A=[0]*4
    for i in range(4):
        A[i]= b[127-4*i] | b[126-4*i]<<8 | b[125-4*i]<<16 | b[124-4*i]<<24
    return A

def my_modmul(a,b,m):
    A=bytes_to_limbs4(a); B=bytes_to_limbs4(b)
    M=[ m[3]|m[2]<<8|m[1]<<16|m[0]<<24,
        m[7]|m[6]<<8|m[5]<<16|m[4]<<24 ]
    MASK=0xFFFFFFFF
    P=[0]*8
    for i in range(4):
        for j in range(4):
            P[i+j]+=A[i]*B[j]
    for i in range(7):
        P[i+1]+=P[i]>>32; P[i]&=MASK
    r_hi=0; r_lo=0
    for i in range(7,-1,-1):
        d2=r_hi; d1=r_lo; d0=P[i]&MASK
        num=(d2<<32)|d1
        q=(num//M[1]) & MASK
        while True:
            lo=M[0]*q; hi=M[1]*q
            t1=(lo>>32)+(hi&MASK); t0=lo&MASK; t2=(hi>>32)+(t1>>32); t1&=MASK
            if not (t2>d2 or (t2==d2 and (t1>d1 or (t1==d1 and t0>d0)))):
                break
            q-=1
        b0=1 if d0<t0 else 0
        n0=(d0-t0)&MASK
        b1=1 if d1 < t1+b0 else 0
        n1=(d1-t1-b0)&MASK
        r_hi=(d2-t2-b1)&MASK
        r_lo=n1
    R=[r_lo,r_hi]
    out=bytearray(128)
    for i in range(4):
        out[127-4*i]=R[i]&0xFF; out[126-4*i]=(R[i]>>8)&0xFF
        out[125-4*i]=(R[i]>>16)&0xFF; out[124-4*i]=(R[i]>>24)&0xFF
    return bytes(out)

def my_modexp(base,exp,m):
    acc=bytearray(128); acc[127]=1
    top=0
    for i in range(31,-1,-1):
        if (exp>>i)&1: top=i; break
    for i in range(top,-1,-1):
        acc=my_modmul(acc,acc,m)
        if (exp>>i)&1: acc=my_modmul(acc,base,m)
    return bytes(acc)

ok=True
for t in range(30):
    a=bytearray(random.getrandbits(8) for _ in range(128)); a[0]=0
    b=bytearray(random.getrandbits(8) for _ in range(128)); b[0]=0
    exp=(int.from_bytes(a,'big')*int.from_bytes(b,'big')%n).to_bytes(128,'big')
    got=my_modmul(a,b,mod)
    if got!=exp:
        ok=False; print("modmul MISMATCH case",t); break
print("modmul all correct:", ok)
ok2=True
for t in range(20):
    base=bytearray(random.getrandbits(8) for _ in range(128)); base[0]=0
    e=random.randint(1,2**40)
    exp=pow(int.from_bytes(base,'big'),e,n).to_bytes(128,'big')
    got=my_modexp(base,e,mod)
    if got!=exp:
        ok2=False; print("modexp MISMATCH case",t); break
print("modexp all correct:", ok2)
