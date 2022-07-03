#!/usr/bin/env python3

# https://ctf.harrisongreen.me/2022/tetctf/crackme_pls/

import angr
import claripy
import capstone
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

code = open('./crackme-pls.bin', 'rb').read()
BASE = 0x400000
p = angr.Project('./crackme-pls.bin')

# 1. Function Table

def find_table_base(function_addr):
    instructions = md.disasm(code[function_addr-BASE:], function_addr)

    for i in range(50):
        t = next(instructions)

        if (t.mnemonic == 'mov' and
            t.op_str.startswith('rax, qword ptr [rip')):

            # e.g.:
            # mov rax, qword ptr [rip + 0x1234]

            off = t.op_str.split('+ ')[1].split(']')[0]
            off = int(off, 16)
            table_base = (t.address + t.size + off)
            return table_base

    return None

# 2. & 3. Key to leaf node mapping

def trace_function(fn_addr, first_comparator, table, code, keyreg='eax'):
    # Prepare the initial state.
    state = p.factory.call_state(addr=fn_addr)
    simgr = p.factory.simulation_manager(state)

    # Single step until we hit the first comparator.
    while True:
        simgr.step(num_inst=1)
        curr = simgr.active[0].addr

        instr = next(md.disasm(code[curr - BASE:], curr))

        # If this is a call, skip it.
        if instr.mnemonic == 'call':
            simgr.active[0].regs.rip += instr.size

            # Unconstrain rax.
            simgr.active[0].regs.rax = claripy.BVS('fake', 64)

        if curr == first_comparator:
            break

    # Step past first instruction (so we can use it in avoid).
    simgr.step(num_inst=1)

    # Clear keyreg
    key_bv = claripy.BVS('key', 32)
    setattr(simgr.active[0].regs, keyreg, key_bv)

    # function -> key
    lookup = {}

    for fn in table:
        fsim = simgr.copy(deep=True)

        # Set avoid=init to prevent looping around.
        fsim.explore(find=fn, avoid=init)

        if len(fsim.found) == 1:
            f = fsim.found[0]

            unique = False
            try:
                # Fails if there is just one solution.
                f.solver.eval_atleast(key_bv, 2)
            except:
                unique = True

            if unique:
                key = f.solver.eval(key_bv)
                lookup[fn] = key

    return lookup
