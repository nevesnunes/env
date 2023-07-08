#!/usr/bin/env python3

import sys

f1_name = sys.argv[1]
f2_name = sys.argv[2]
f_out_name = "out.bin" if len(sys.argv) < 4 else sys.argv[3]

with open(f1_name, "rb") as f1, open(f2_name, "rb") as f2:
    f1_bytes = f1.read()
    f2_bytes = f2.read()
o = bytearray(len(f1_bytes) + len(f2_bytes))
i = 0
for a, b in zip(f1_bytes, f2_bytes):
    o[i] = a
    i += 1
    o[i] = b
    i += 1
with open(f_out_name, "wb") as f_out:
    f_out.write(o)
