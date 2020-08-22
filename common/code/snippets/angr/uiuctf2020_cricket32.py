#!/usr/bin/env python3


import angr
import claripy

# copy implementation from https://medium.com/@chenfelix/crc32c-algorithm-79e0a7e33f61
def get_crc32_calc_BVV(i):
    crc = i.zero_extend(32 - i.size())
    if isinstance(crc, angr.state_plugins.sim_action_object.SimActionObject):
        crc = crc.to_claripy()
    for j in range(8):
        shift = (crc >> 1) & 0x7FFFFFFF
        cond = crc & 1 > 0
        crc = claripy.If(cond, shift ^ 0x82F63B78, shift)
    return crc


def crc32c(dst, src):
    b32 = src
    crc = dst
    for i in [3, 2, 1, 0]:
        b = b32.get_byte(i)
        shift = (crc >> 8) & 0x00FFFFFF
        onebyte = crc.get_byte(3)
        crc = get_crc32_calc_BVV(onebyte ^ b) ^ shift
    return crc


def crc32_hook(state):
    crc = state.regs.edx
    addr = state.regs.esi
    b32 = state.memory.load(addr).reversed
    print("CRC32 accessing ", b32)
    state.regs.edx = crc32c(crc, b32)


project = angr.Project("./cricket32", auto_load_libs=True)

flag_len = 32
arg1 = claripy.BVS("arg1", flag_len * 8)
for b in arg1.chop(8):
    initial_state.add_constraints((b == 0) | ((b > 31) & (b < 127)))
for i in range(len("uiuctf{")):
    b = arg1.chop(8)[i]
    initial_state.add_constraints(b == ord("uiuctf{"[i]))

initial_state = project.factory.entry_state(args=["./cricket32", arg1])

project.hook(0x4012A2, crc32_hook, length=5)

sm = project.factory.simulation_manager(initial_state)
sm.explore(avoid=[0x40128D])

for sol in sm.deadended:
    print(sol.posix.dumps(1))
    sol.make_concrete_int(arg1).to_bytes(32, "big")
