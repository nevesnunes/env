#!/usr/bin/env python3

import struct
import sys

v = b""
for i in sys.stdin.readlines():
    i = i.strip()
    v += bytes.fromhex(hex(struct.unpack("<I", struct.pack(">I", int(i, 16)))[0])[2:])
    # ||
    # from pwn import *
    # v += p32(int(i, 16))
sys.stdout.buffer.write(v)
