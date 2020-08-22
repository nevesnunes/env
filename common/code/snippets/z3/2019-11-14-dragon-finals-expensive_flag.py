#!/usr/bin/env python3

import z3


def generate_moves_for_value(target):
    last_positions = [(z3.BitVec('x%d' % i, 64),
                       z3.BitVec('y%d' % i, 64),
                       z3.BitVec('dir%d' % i, 64)) for i in range(10)]
    s = z3.Solver()
    for x, y, direction in last_positions:
        s.add(x < 428)
        s.add(x >= 420)
        s.add(y < 185)
        s.add(y >= 180)
        s.add(direction < 4)
        s.add(direction >= 0)
    n = 0xf0e1d2c3
    for a, b, c in last_positions:
        k = a ^ (b << 8) ^ (c << 16)
        n = ((n << 3) ^ k) & 0xffffffff
    s.add(n == target)
    print(s.check())
    model = s.model()
    print(s.__repr__())
    results = []
    for x, y, direction in last_positions:
        results.append((model[x].as_long(),
                        model[y].as_long(),
                        model[direction].as_long()))
    return results

print(generate_moves_for_value(345))
