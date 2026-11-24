import random
random.seed(5)
mod = bytearray(open('rsa_mod.bin','rb').read())
n = int.from_bytes(mod,'big')
B = 1<<32

def limbs_of(b128):
    L=[0]*4
    for i in range(4):
        L[i]= b128[3+4*i] | b128[2+4*i]<<8 | b128[1+4*i]<<16 | b128[0+4*i]<<24
    return L

def divmod_limb(D, M):
    # D: 8 limbs (little), M: 4 limbs (little), M[3]!=0
    # normalize
    sh=0
    while (M[3] << (sh+1)) < (1<<31): sh+=1
    d=1<<sh
    # M2 = M*d (4 limbs)
    M2=[0]*4; carry=0
    for i in range(4):
        v=M[i]*d+carry; M2[i]=v&B-1; carry=v>>32
    # D2 = D*d (9 limbs)
    D2=[0]*9; carry=0
    for i in range(8):
        v=D[i]*d+carry; D2[i]=v&B-1; carry=v>>32
    D2[8]=carry
    # long division: 9-limb D2 by 4-limb M2 (M2[3] >= 2^31)
    Q=[0]*6  # quotient up to 9-4+1=6 limbs? actually 9-4=5, plus
    R=[0]*4
    for j in range(8, 3, -1):   # j = 8,7,6,5,4
        # numerator = (R shifted) ... standard: bring down D2[j]
        # current top: (R[3],R[2],R[1],R[0]) then shift left 32, OR D2[j]
        # shift R left
        carry=0
        for i in range(3,-1,-1):
            v=(R[i]<<32)|carry
            R[i]=v&B-1
            carry=v>>32
        R[3]=carry  # (top from shift) then we will treat the numerator as (R[3],R[2],D2[j])? 
        # Standard Knuth: for j, the dividend digit D2[j] comes down; numerator = (old_R_high * B + ...) 
        # Let me use the explicit form: numerator N = (R[3], R[2]) combined with D2[j]? 
        # Actually the correct bring-down: R = (R * B + D2[j]) mod M, and we add to quotient.
        # Let me instead do: N = R*B + D2[j]  (5 limbs: (R3<<32)+ ... )
        # then qhat = N / M (leading part)
        N0=D2[j]
        N1=R[0]
        N2=R[1]
        N3=R[2]
        N4=R[3]
        # N = (N4,N3,N2,N1,N0) 5 limbs, M=(M2[3],M2[2],M2[1],M2[0]) 4 limbs
        # qhat estimate from top 2 limbs of N over M2[3]:
        if N4 == 0:
            # N is 4 limbs (N3..N0); qhat from (N3*B+N2)/M2[3]
            qhat=( (N3<<32)|N2 ) // M2[3]
        else:
            qhat=( (N4<<32)|N3 ) // M2[3]
        qhat=B-1 if qhat>=B else qhat
        # correct: while qhat*M >= N: qhat--
        # compute qhat*M (5 limbs) and compare to N (5 limbs)
        while True:
            # qhat * M2
            pm=[0]*5; c=0
            for i in range(4):
                v=qhat*M2[i]+c; pm[i]=v&B-1; c=v>>32
            pm[4]=c
            # compare pm (5) vs N (5: N4,N3,N2,N1,N0)
            big = pm[4]>N4 or (pm[4]==N4 and (pm[3]>N3 or (pm[3]==N3 and (pm[2]>N2 or (pm[2]==N2 and (pm[1]>N1 or (pm[1]==N1 and pm[0]>N0)))))))
            if not big: break
            qhat-=1
        # N -= qhat*M ; store quotient limb
        # N (5 limbs) - pm (5 limbs)
        sub=[0]*5; c=0
        for i in range(5):
            v=Nlist(N,i)-pm[i]-c
            sub[i]=v&B-1
            c=1 if v<0 else 0
        R=sub[1:5]  # wait, remainder is the low 4 limbs of (N - qhat*M)
        R=[sub[0],sub[1],sub[2],sub[3]]
        Q[j-4]=qhat
    # de-normalize remainder: R / d
    # R (4 limbs) // d
    rr=(R[3]<<96)|(R[2]<<64)|(R[1]<<32)|R[0]
    Rv=rr//d
    Rl=[0]*4
    for i in range(4): Rl[i]= (Rv>>(32*i))&0xFFFFFFFF
    Qv=(Q[5]<<160)|(Q[4]<<128)|(Q[3]<<96)|(Q[2]<<64)|(Q[1]<<32)|Q[0]
    return Qv, Rl

def Nlist(N,i):
    return [N0,N1,N2,N3,N4][i]

def my_modmul(a,b,m):
    A=limbs_of(a); B4=limbs_of(b); M=limbs_of(m)
    P=[0]*8
    for i in range(4):
        for j in range(4):
            P[i+j]+=A[i]*B4[j]
    for i in range(7):
        P[i+1]+=P[i]>>32; P[i]&=B-1
    Q,R=divmod_limb(P,M)
    return R

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
for t in range(20):
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
