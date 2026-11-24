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
# absolute VA -> file (va-0x10000000 is rva)
def va2file(va): return rva2file(va-0x10000000)
def str_at_va(va,n=160):
    f=va2file(va)
    if f is None: return b''
    return d[f:f+n].split(b'\0')[0]
def find(sub):
    idx=d.find(sub)
    return idx

# --- country/language table: (ptr, lang) at RVA 0x153E0 ---
print("=== country groups ===")
groups=[]
k=0
while True:
    f=rva2file(0x153E0+k)
    ptr=u32(f); lang=u32(f+4)
    if ptr==0 and lang==0: break
    if not (0x10000000 < ptr < 0x10010000):
        # end of table (junk after)
        break
    # ptr -> list of 2-char country codes, NUL-terminated
    cf=va2file(ptr)
    codes=[]
    p=0
    while d[cf+p+1] != 0:
        codes.append(d[cf+p:cf+p+2].decode('latin1')); p+=2
    groups.append((lang,codes))
    k+=8
for lang,codes in groups:
    print("  0x%04x  %s"%(lang,' '.join(codes)))

# save as header
out=[]
out.append("/* Auto-generated: country -> language groups (23 groups) from the worm @RVA 0x153E0 */")
out.append("/* Each group: language id + list of 2-letter country codes. target_language() picks the */")
out.append("/* first group listing the target's country; unknown->English(9); UA handled specially(0). */")
out.append("#ifndef KIDO_COUNTRY_H")
out.append("#define KIDO_COUNTRY_H")
out.append("#include <stdint.h>")
out.append("typedef struct { int lang; const char* code; } kido_cc_t;")
for i,(lang,codes) in enumerate(groups):
    out.append("static const kido_cc_t g_grp%d[] = {"%i)
    for c in codes:
        out.append('    { 0x%04X, "%s" },'%(lang,c))
    out.append("    { 0, NULL }"); out.append("};")
out.append("static const kido_cc_t* const g_country_groups[%d] = {"%len(groups))
for i in range(len(groups)):
    out.append("    g_grp%d,"%i)
out.append("};")
out.append("#define KIDO_COUNTRY_GROUPS %d"%len(groups))
out.append("#endif")
open('kido_country.h','w').write("\n".join(out)+"\n")
print("\nwrote kido_country.h (%d groups)"%len(groups))
