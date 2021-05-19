#!/usr/bin/env python3

# Usage:

# b=; while true; do read -r i; [ -z "$i" ] && break; asm=$(rasm2 -a x86 -b32 "$i" | tee /dev/tty); b+="$asm"; done; echo "$b" | xxd -r -p | ./trace.py

# echo '
# mov ax,0xff
# cmp ax,0xff
# jl 0x41414141
# jb 0x41414141
# ' | while read -r i; do [ -n "$i" ] && rasm2 -a x86 -b 32 "$i"; done | paste -sd "" | xxd -r -p | ./trace.py

# from keystone import *
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from capstone.x86 import *
import sys

# memory address where emulation starts
ADDRESS = 0x1000000

# assembler, disassembler, and emulator objects
# ks = Ks(KS_ARCH_X86, KS_MODE_32)
cs = Cs(CS_ARCH_X86, CS_MODE_32)
mu = Uc(UC_ARCH_X86, UC_MODE_32)


# yield successive n-sized chunks from lst
def chunks(lst, n=4):
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


def trace_flags(uc):
    eflags = uc.reg_read(UC_X86_REG_EFLAGS)
    active_flags = []
    bits = {
        0: "CF",
        2: "PF",
        4: "AF",
        6: "ZF",
        7: "SF",
        8: "TF",
        9: "IF",
        10: "DF",
        11: "OF",
        12: "IPL",
        13: "OPL",
        14: "NT",
        16: "RF",
        17: "VM",
    }
    for bit in bits.keys():
        if eflags & (1 << bit) > 0:
            active_flags.append(f"{bits[bit]}")

    out = " ".join(active_flags)
    if not out.strip():
        out = "-"

    print(f"| {out}")


def trace_registers(uc):
    registers = {
        "eax": uc.reg_read(UC_X86_REG_EAX),
        "ebx": uc.reg_read(UC_X86_REG_EBX),
        "ecx": uc.reg_read(UC_X86_REG_ECX),
        "edx": uc.reg_read(UC_X86_REG_EDX),
        "esi": uc.reg_read(UC_X86_REG_ESI),
        "edi": uc.reg_read(UC_X86_REG_EDI),
        "ebp": uc.reg_read(UC_X86_REG_EBP),
        "esp": uc.reg_read(UC_X86_REG_ESP),
    }
    for chunk in chunks(list(registers.keys())):
        print(
            "| "
            + " ".join([f"{key}={hex(registers[key])[2:].ljust(8)}" for key in chunk])
        )


def trace_instruction(uc, address, size):
    code = uc.mem_read(address, size)
    asm = "".join([f"{x.mnemonic} {x.op_str}" for x in cs.disasm(code, size)])
    print(f"{hex(address)} {asm}")


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" % (address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    trace_instruction(uc, address, size)
    trace_flags(uc)
    trace_registers(uc)


# callback for tracing invalid memory access (READ or WRITE)
def hook_mem_invalid(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE_UNMAPPED:
        print(
            ">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x"
            % (address, size, value)
        )
        # map this memory in with 2MB in size
        uc.mem_map(0xAAAA0000, 2 * 1024 * 1024)
        # return True to indicate we want to continue emulation
        return True
    else:
        # return False to indicate we want to stop emulation
        return False


# callback for tracing memory access (READ or WRITE)
def hook_mem_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print(
            ">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x"
            % (address, size, value)
        )
    else:  # READ
        print(">>> Memory is being READ at 0x%x, data size = %u" % (address, size))


def test_i386(code):
    try:
        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, code)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_EAX, 0x0)
        mu.reg_write(UC_X86_REG_EBX, 0x0)
        mu.reg_write(UC_X86_REG_ECX, 0x0)
        mu.reg_write(UC_X86_REG_EDX, 0x0)
        mu.reg_write(UC_X86_REG_ESI, 0x0)
        mu.reg_write(UC_X86_REG_EDI, 0x0)
        mu.reg_write(UC_X86_REG_EBP, 0x0)
        mu.reg_write(UC_X86_REG_ESP, 0x0)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(code))

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == "__main__":
    code = sys.stdin.buffer.read()
    test_i386(code)
