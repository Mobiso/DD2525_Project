#Helper script when testing mutator
import sys
import pdf_exploder
import random
path = sys.argv[1]
with open(path,"rb") as f:
    buf = f.read()
pdf_exploder.init(random.randint(0,100000))
mutated = pdf_exploder.fuzz(buf,b'',len(buf)*2)
with open("out","wb") as f2:
    f2.write(mutated)
