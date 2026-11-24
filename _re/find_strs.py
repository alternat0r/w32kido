import struct
d=open('stage3_out/stage2_copy.dll','rb').read()
def u32(o): return struct.unpack_from('<I',d,o)[0]
def u16(o): return struct.unpack_from('<H',d,o)[0]
e=u32(0x3C); o=e+24
soh=u16(e+20); nsec=u16(e+6); so=o+soh
secs=[]
for i in range(nsec):
    nm=d[so:so+8].rstrip(b'\0').decode('latin1')
    vs=u32(so+8); va=u32(so+12); rs=u32(so+16); rp=u32(so+20)
    secs.append((nm,va,vs,rp,rs)); so+=40
for pat in [b'Global\\%u-%u', b'Global\\%d-%d', b'%08x%08x', b'Global\\', b'%u-%u', b'%u-7']:
    idx=0; found=[]
    while True:
        idx=d.find(pat,idx)
        if idx<0: break
        found.append(hex(idx)); idx+=1
    print(pat, "len",len(pat), "->", found[:5])
def findw(sub):
    sub2=sub.encode('utf-16-le')
    idx=0; res=[]
    while True:
        idx=d.find(sub2,idx)
        if idx<0: break
        res.append(hex(idx)); idx+=1
    return res
for w in [r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost',
          r'system32\svchost.exe -k ',
          'netsvcs',
          r'CurrentControlSet\Services',
          r'Microsoft\Windows\CurrentVersion\Nls',
          'ServiceDll', 'ImagePath', 'ObjectName', 'LocalSystem',
          'DisplayName', 'ErrorControl', 'Parameters', 'Start', 'Type',
          'SharedAccess', 'ResetSR', 'srclient.dll',
          r'\Microsoft\Windows NT\CurrentVersion\SvcHost']:
    print("W", w, "->", findw(w)[:3])
