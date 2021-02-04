#!/usr/bin/env python3

from capstone import *

# 0x1000: endbr64
# 0x1004: xor     ebp, ebp
# 0x1006: mov     r9, rdx
# 0x1009: pop     rsi
CODE = b"\xf3\x0f\x1e\xfa\x31\xed\x49\x89\xd1\x5e"

try:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(CODE, 0x1000):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

except CsError as e:
    print("ERROR: %s" % e)
