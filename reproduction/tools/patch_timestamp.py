#!/usr/bin/env python3
# patch_timestamp.py - set a PE's TimeDateStamp DWORD to an exact value.
# Usage: patch_timestamp.py <file> <hexstamp>   e.g. patch_timestamp.py kido_worm.dll 0x3F73A4C6
import sys, struct
f = sys.argv[1]
ts = int(sys.argv[2], 16)
d = bytearray(open(f, 'rb').read())
e = struct.unpack_from('<I', d, 0x3C)[0]
old = struct.unpack_from('<I', d, e + 8)[0]
struct.pack_into('<I', d, e + 8, ts)
open(f, 'wb').write(bytes(d))
print('%s: timestamp 0x%08X -> 0x%08X' % (f, old, ts))
