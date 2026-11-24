s=open('test_red.c').read()
s=s.replace('REDUCTION OK\n','REDUCTION OK\\n')
s=s.replace('REDUCTION BAD\n','REDUCTION BAD\\n')
s=s.replace('exp=%02X\n','exp=%02X\\n')
open('test_red.c','w').write(s)
print("fixed; check:")
for i,line in enumerate(open('test_red.c').read().splitlines()[17:22],18):
    print(i, line[:60])
