#!/usr/bin/env python3

import sys

with open(sys.argv[1], "rb") as f:
    a = bytearray(f.read())
    l = len(a) & ~1
    a[1:l:2], a[:l:2] = a[:l:2], a[1:l:2]

    with open(sys.argv[2], "wb") as f_out:
        f_out.write(a)
