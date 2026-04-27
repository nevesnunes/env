#!/usr/bin/env python3

import sys

filename = sys.argv[1]
filename_swapped = f"{filename}.swapped" if len(sys.argv) == 2 else sys.argv[2]

with open(filename, "rb") as f:
    a = bytearray(f.read())

l = len(a) & ~1
for i in range(0, l, 2):
    x0 = a[i + 0]
    x1 = a[i + 1]
    a[i + 0] = x1
    a[i + 1] = x0

with open(filename_swapped, "wb") as f_out:
    f_out.write(a)
