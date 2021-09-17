#!/usr/bin/env python3

from z3 import *

x = Int('x')
g = Goal()
g.add(x < 5, x < 4, x < 3, x == 1)
for t in tactics():
    try:
        print(t, Tactic(t)(g)[0])
    except:
        pass
