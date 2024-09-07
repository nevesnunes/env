#!/usr/bin/env python3

from z3 import *
import ipdb

s = Solver()

a = Real("a")
b = Real("b")

s.add(a + b == 1)
s.add(a * a + b * b == 9)
#s.add(a * b == -4)

while (s.check() == sat):
    #ipdb.set_trace()
    print(s.model())
    print(s.model()[a].sexpr(), s.model()[a].poly())
    print(s.model()[b].sexpr(), s.model()[b].poly())
    print(pow(float(str(s.model()[a]).strip('?')),4) + pow(float(str(s.model()[b]).strip('?')),4))
    s.add(a != s.model()[a], b != s.model()[b])
