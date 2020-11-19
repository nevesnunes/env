#!/usr/bin/env python3

# import elftools
# from elftools.elf.elffile import ELFFile
# 
# def is_pie(filename):
#     with open(filename, 'rb') as file:
#         elffile = ELFFile(file)
#         base_address = next(seg for seg in elffile.iter_segments() if seg['p_type'] == "PT_LOAD")['p_vaddr']
#         return elffile.elftype == 'DYN' and base_address == 0

from pwn import *
import angr
import claripy
import sys

START = 0x001080 # entrypoint
FIND  = 0x0011f4 # Good job message basic block
AVOID = [0x00117f, 0x0011e8] # Wrong messages bassic block

BUF_LEN = 104 * 8


def char(state, c):
    return state.solver.And(c <= '~', c >= ' ')


def main():
    filename = sys.argv[1]
    e = ELF(filename)
    p = None
    if e.pie:
        p = angr.Project(filename, main_opts={'custom_base_addr': 0})
    else:
        p = angr.Project(filename)

    flag = claripy.BVS('flag', BUF_LEN)
    state = p.factory.blank_state(addr=START, stdin=flag)

    for c in flag.chop(8):
        state.solver.add(char(state, c))

    ex = p.factory.simulation_manager(state)
    ex.use_technique(angr.exploration_techniques.Explorer(find=FIND, avoid=AVOID))

    ex.run()

    for errored in ex.errored:
        error = errored.error
        print(error.bbl_addr)
        print(error.stmt_idx)
        print(error)
    for found in ex.found:
        return found.posix.dumps(0).decode("latin-1")


if __name__ == '__main__':
    print("flag: {}".format(main()))
