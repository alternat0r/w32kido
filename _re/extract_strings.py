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
def rva2file(rva):
    for nm,va,vs,rp,rs in secs:
        if va<=rva<va+vs:
            off=rva-va
            if off<rs: return rp+off
    return None
def a(rva,n=200):
    f=rva2file(rva)
    if f is None: return b''
    return d[f:f+n].split(b'\0')[0]
def aw(off,n=200):  # wide from file offset
    b=d[off:off+n]
    for i in range(0,len(b)-1,2):
        if b[i]==0 and b[i+1]==0: return b[:i]
    return b
# ASCII strings by (name, rva)
A = [
 ('S_IP_LOOKUP1',0x138C),('S_IP_LOOKUP2',0x13A4),('S_IP_LOOKUP3',0x13BC),
 ('S_SELF_URL',0x14BC),('S_IPC',0x14D8),('S_NCACN',0x1500),
 ('S_PIPE_SRVSVC',0x151C),('S_PIPE_BROWSER',0x154C),
 ('S_SMB_NETBIOS',0x19C3),('S_NTLM',0x1A34),('S_LANMAN',0x1A86),
 ('S_OS_UNIX',0x1A90),('S_OS_WIN40',0x1A98),('S_OS_WIN50',0x1AA4),
 ('S_OS_WIN51',0x1AB0),('S_OS_SP2',0x1ABC),('S_OS_WS2003',0x1ACC),
 ('S_OS_VISTA',0x1B00),('S_OS_SP',0x1AE0),('S_OS_SP1',0x1AF0),
 ('S_HTTP_200',0x1B18),('S_USER_AGENT',0x1B80),('S_GET_SLASH',0x1B98),
 ('S_DATE_W3',0x18E0),('S_DATE_ASK',0x18E8),('S_DATE_MSN',0x18F0),
 ('S_DATE_YAHOO',0x18F8),('S_DATE_GOOGLE',0x1904),('S_DATE_BAIDU',0x1910),
 ('S_TLD_BIZ',0x1888),('S_TLD_INFO',0x1890),('S_TLD_ORG',0x1898),
 ('S_TLD_NET',0x18A0),('S_TLD_COM',0x18A8),
 ('S_HTTP_WWW',0x1924),('S_TRAFFIC_EXE',0x195C),('S_TRAFFIC_HOST',0x1998),
 ('S_GEOIP',0x3E3C),('S_GET_HTTP11',0x61C0),
 ('S_MSEARCH',0x63A8),('S_LOC',0x6460),('S_IGD',0x6428),('S_ROOTDEV',0x6418),
 ('S_SOAPPOST',0x62D0),('S_CONTENTLEN',0x6398),
 ('S_WANPPP',0x6200),('S_WANIP',0x6230),('S_WANCI',0x6260),
 ('S_SCPDURL',0x6298),('S_EVTSUBURL',0x62A0),('S_CTRLURL',0x62AC),
 ('S_SRVCETYPE',0x62B8),('S_URLBASE',0x62C4),('S_MCAST',0x6620),
 ('S_SOAP_ENV1',0x6498),('S_SOAP_ENV2',0x6548),
 ('S_NETPW',0x15BC),('S_NETAPI32',0x15D4),
 ('S_SERVICES_EXE',0x604,'a04'),
 ('S_NLS',0x614,'a1d'),('S_SHAREDACCESS',0x644,'a44'),('S_RESETSR',0x684,'a84'),('S_SRCLIENT',0x68c,'a8c'),
]
# Wide strings (file offset)
W = [
 ('W_SVCHOST',0xab0),('W_SVCHOST_IMG',0xc42),('W_NETSVCS',0xc78),
 ('W_SVC_BASE',0xbee),('W_SERVICE_DLL',0xb1c),('W_IMAGE_PATH',0xb7c),
 ('W_OBJECT_NAME',0xb4c),('W_LOCAL_SYSTEM',0xb64),('W_DISPLAY_NAME',0xbc4),
 ('W_ERROR_CONTROL',0xb90),('W_PARAMETERS',0xb34),('W_START',0xbac),('W_TYPE',0xbb8),
]
out=["/* Auto-generated: EXACT byte-for-byte strings recovered from the worm (stage 3). */",
"/* Every literal below is copied verbatim from the unpacked Conficker image. */",
"#ifndef KIDO_STRINGS_H","#define KIDO_STRINGS_H","#include <stdint.h>"]
def cstr(b):
    r=b.decode('latin1')
    r=r.replace('\\','\\\\').replace('"','\\"').replace('\r','\\r').replace('\n','\\n')
    return '"'+r+'"'
out.append("")
out.append("/* ---- ASCII strings ---- */")
for ent in A:
    name,rva = ent[0],ent[1]
    foff = ent[2] if len(ent)>2 else None
    if foff is not None:
        f=int(foff,16); b=d[f:f+200].split(b'\0')[0]
    else:
        b=a(rva)
        if not b and rva<len(d):
            b=d[rva:rva+200].split(b'\0')[0]
    out.append('static const char %s[] = %s; // RVA 0x%X'%(name,cstr(b),rva))
out.append("")
out.append("/* ---- UTF-16LE (wide) strings ---- */")
for name,off in W:
    b=aw(off)
    try: txt=b.decode('utf-16-le')
    except: txt=b.decode('latin1')
    # emit as wide C literal
    wide=''
    for ch in txt:
        wide += 'L"'+ch+'"'  # not ideal
    # simpler: emit as byte array
    out.append('static const uint8_t %s[] = {'%name)
    for i in range(0,len(b),16):
        out.append('    '+', '.join('0x%02X'%x for x in b[i:i+16])+',')
    out.append('}; // wide "%s"  file 0x%X'%(txt,off))
# pointer arrays: date sites, TLD, IP sites  (as string literals in fixed order matching report)
out.append("")
out.append("/* ---- pointer arrays (fixed order as in the worm) ---- */")
out.append('static const char* const g_tld[] = { "%s", "%s", "%s", "%s", "%s", 0 };'%(
  a(0x1888),a(0x1890),a(0x1898),a(0x18A0),a(0x18A8)))
out.append('static const char* const g_ip_sites[] = { "%s", "%s", "%s", 0 };'%(
  a(0x138C),a(0x13A4),a(0x13BC)))
out.append('static const char* const g_date_sites[] = { "%s", "%s", "%s", "%s", "%s", "%s", 0 };'%(
  a(0x18E0),a(0x18E8),a(0x18F0),a(0x18F8),a(0x1904),a(0x1910)))
out.append("#define KIDO_TLD_COUNT 5")
out.append("#define KIDO_IP_SITES 3")
out.append("#define KIDO_DATE_SITES 6")
out.append("#endif")
open('kido_strings.h','w').write("\n".join(out)+"\n")
print("wrote kido_strings.h")
# verify a couple
for ent in A:
    name,rva = ent[0],ent[1]
    foff = ent[2] if len(ent)>2 else None
    if foff is not None:
        f=int(foff,16); b=d[f:f+200].split(b'\0')[0]
    else:
        b=a(rva)
        if not b and rva<len(d): b=d[rva:rva+200].split(b'\0')[0]
    if not b: print("  WARN empty",name,hex(rva))
import shutil
shutil.copy('kido_strings.h','E:/projects/analysis/2026-w32kido/reproduction/src/worm/kido_strings.h')
print("copied")
