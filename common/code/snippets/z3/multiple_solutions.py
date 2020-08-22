#!/usr/bin/env python3

from z3 import *

s = Solver()

x = BitVec("x", 32)
y = BitVec("y", 32)
z = BitVec("z", 32)
a = BitVec("a", 32)
b = BitVec("b", 32)
c = BitVec("c", 32)

s.add(x != 0)
s.add(x == a ^ b * z * (y >> c))

while (s.check() == sat):
    print(s.model())
    s.add(x != s.model()[x], y != s.model()[y])
