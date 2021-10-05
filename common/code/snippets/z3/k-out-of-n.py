#!/usr/bin/env python3

import z3

s = z3.Solver()
bvars = [z3.Bool("Var {0}".format(x)) for x in range(10)]
# Exactly 3 of the variables should be true
s.add(z3.PbEq([(x, 1) for x in bvars], 3))
s.check()
m = s.model()

s = z3.Solver()
bvars = [z3.Bool("Var {0}".format(x)) for x in range(10)]
# <=3 of the variables should be true
s.add(z3.PbLe([(x, 1) for x in bvars], 3))
s.check()
m = s.model()

s = z3.Solver()
bvars = [z3.Bool("Var {0}".format(x)) for x in range(10)]
# >=3 of the variables should be true
s.add(z3.PbGe([(x, 1) for x in bvars], 3))
s.check()
m = s.model()
