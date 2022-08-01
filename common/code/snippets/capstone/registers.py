#!/usr/bin/env python3

import capstone

def has_write_to_dereference_of_register(
    instruction: capstone.CsInsn,
    register: int
) -> bool:
    for operand in instruction.operands:
        if operand.access & capstone.CS_AC_WRITE:
            if operand.type == capstone.CS_OP_REG:
                if operands.value.reg == register:
                    return True
            elif operand.type == capstone.CS_OP_MEM:
                mem = operand.value.mem
                if mem.base == register or mem.index == register:
                    return True
    return False

Cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
Cs.detail = True

CODE = b"\x48\x89\x44\x24\x10"
for i in Cs.disasm(CODE, 0):
    reads, writes = i.regs_access()

    print(f'reads = {reads}, writes = {writes}')
