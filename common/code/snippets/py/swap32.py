#!/usr/bin/env python3

import sys

filename = sys.argv[1]
filename_swapped = f"{filename}.swapped" if len(sys.argv) == 2 else sys.argv[2]

with open(filename, "rb") as f:
    a = bytearray(f.read())

l = len(a) & ~1
for i in range(0, l, 4):
    x0 = a[i + 0]
    x1 = a[i + 1]
    x2 = a[i + 2]
    x3 = a[i + 3]
    a[i + 0] = x2
    a[i + 1] = x3
    a[i + 2] = x0
    a[i + 3] = x1

with open(filename_swapped, "wb") as f_out:
    f_out.write(a)
