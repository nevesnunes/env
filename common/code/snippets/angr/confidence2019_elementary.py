#!/usr/bin/env python3

import angr
import claripy
import sys

# angr uses 0x400000 as base address for PIE executables

# START = 0x400610 # entrypoint
START = 0x40071a  # start of main
#START = 0x400745
FIND = 0x40076f
# FIND  = 0x40077f # Good job message basic block
#AVOID = []
AVOID = [0x400786]  # Wrong messages bassic block
with open(sys.argv[2], "r") as fin:
    for l in fin:
        # add other addresses to avoid, all those "mov eax, 0"
        AVOID.append(0x400000 + int(l.strip(), 16))

BUF_LEN = 128


def char(state, c):
    return state.solver.And(c <= '~', c >= ' ')


def main():
    p = angr.Project(sys.argv[1])

    flag = claripy.BVS('flag', BUF_LEN * 8)
    state = p.factory.blank_state(addr=START, stdin=flag)

    for c in flag.chop(8):
        state.solver.add(char(state, c))

    ex = p.factory.simulation_manager(state)
    ex.use_technique(angr.exploration_techniques.Explorer(find=FIND, avoid=AVOID))

    ex.run()

    print(ex)
    for errored in ex.errored:
        error = errored.error
        print(error.bbl_addr)
        print(error.stmt_idx)
        print(error)
    return ex.found[0].posix.dumps(0).decode("utf-8")


if __name__ == '__main__':
    print("flag: {}".format(main()))
