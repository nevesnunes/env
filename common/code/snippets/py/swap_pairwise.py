#!/usr/bin/env python3

import sys

filename = sys.argv[1]
filename_swapped = f"{filename}.swapped" if len(sys.argv) == 2 else sys.argv[2]

with open(filename, "rb") as f:
    a = bytearray(f.read())
    l = len(a) & ~1
    a[1:l:2], a[:l:2] = a[:l:2], a[1:l:2]

    with open(filename_swapped, "wb") as f_out:
        f_out.write(a)
