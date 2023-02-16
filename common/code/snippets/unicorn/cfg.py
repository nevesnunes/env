#!/usr/bin/env python3

import cle
from capstone import *
import pprint

pp = pprint.PrettyPrinter(depth=4)

binary = cle.Loader("file")
main_obj = binary.main_object
nodes = {}
edges = []
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def explore_bblock(addr):
    if addr in nodes.keys():
        return ()
    block = []
    exits = []
    address = addr
    while True:
        data = binary.memory.load(address, 15)
        instr = list(md.disasm(data, address, 0))[0]
        instr._CsInsn__gen_detail()
        address = address + instr.size
        block.append(instr)
        if instr.mnemonic == "ret":
            nodes[addr] = block
            return ()
        if instr.group(CS_GRP_JUMP):
            nodes[addr] = block
            edges.append((addr, instr.operands[0].imm))
            if instr.mnemonic == "jmp" and instr.operands[0].type == CS_OP_IMM:
                return (instr.operands[0].imm,)
            elif instr.operands[0].type == CS_OP_IMM:
                edges.append((addr, address))
                return address, instr.operands[0].imm


scheduled = set(explore_bblock(addr))

while len(scheduled) != 0:
    addr = scheduled.pop()
    scheduled.update(explore_bblock(addr))
pp.pprint(nodes)
