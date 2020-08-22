#!/usr/bin/env python3

import angr
import claripy


def AND1(c):
    """constrain 1: printable"""
    return claripy.And(33 <= c, c <= 126)


def AND2(c):
    """returns constraints s.t. c is printable"""
    return claripy.And(65 <= c, c <= 90)


def AND3(c):
    """returns constraints s.t. c is printable"""
    return claripy.And(97 <= c, c <= 122)


p = angr.Project("prodkey")

verify_function = 0x00400C99
state = p.factory.blank_state(addr=verify_function)

length = 29
flag = claripy.BVS("flag", length * 8)

for i in range(length):
    state.solver.add(AND1(flag.get_byte(i)))
    # state.solver.add( AND2(flag.get_byte(i)) )
    # state.solver.add( AND3(flag.get_byte(i)) )

my_buf = 0x12345678
state.memory.store(addr=my_buf, data=flag)
state.regs.rdi = my_buf


@p.hook(0x00400CA9)
def debug_func(state):
    rdi_value = state.regs.rdi
    print("rdi is point to {}".format(rdi_value))


simgr = p.factory.simulation_manager(state)

good = 0x00400DEB
bad = 0x00400DF2

simgr.explore(find=good, avoid=bad)

result = simgr.found[0]

# Always print this
for i in range(3):
    print(result.posix.dumps(i))

print(result.solver.eval(flag, cast_to=bytes))
