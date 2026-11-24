import random
random.seed(1)

# reduction: rem(256) mod m(128), m in high 128
def reduce(prod, m):
    m=list(m); rem=[0]*256; n=int.from_bytes(bytes(m),'big')
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

# small test: m = 256 (0x0100 as 128-byte), prod = 1000
m=bytearray(128); m[126]=1; m[127]=0   # value 256
prod=bytearray(256); prod[255]=1000
got=reduce(prod,m)
exp=(1000 % 256).to_bytes(128,'big')
print("small test:", got==exp, "got low", list(got[-4:]), "exp low", list(exp[-4:]))

# m=7
m=bytearray(128); m[127]=7
prod=bytearray(256); prod[255]=1000
got=reduce(prod,m); exp=(1000%7).to_bytes(128,'big')
print("m=7 test:", got==exp)
