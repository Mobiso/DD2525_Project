#Helper script to test the mutator
import sys
import png_mutator
import random


path = sys.argv[1]

with open(path, "rb") as f:
    buf = f.read()


#png_mutator.init(123)
mutated = png_mutator.fuzz(buf, b'', 1024)

with open("outpng.png", "wb") as f2:
    f2.write(mutated)

# print(mutated)

