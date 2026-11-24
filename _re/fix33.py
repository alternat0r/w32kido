s=open('test_red33.c').read()
# strip the broken REDUCTION_OK/BAD block and keep just the R dump
import re
# remove everything from ' int ok=1;' through end, then append clean dump+return
idx=s.index(' int ok=1;')
s=s[:idx]
s=s.rstrip()
s += '\n for(int k=17;k>=0;k--)printf("RK%d=%016llX\\n",k,(unsigned long long)R[k]);\n return 0;}\n'
open('test_red33.c','w').write(s)
print("cleaned; tail:")
print(s[-260:])
