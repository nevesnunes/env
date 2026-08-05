#!/usr/bin/env python3

from pathlib import Path
import sys

filename = sys.argv[1]
parent_dir = Path(filename).parent
output_dir = parent_dir / 'swapped'
output_dir.mkdir(parents=True, exist_ok=True)

with open(filename, "rb") as f:
    a = bytearray(f.read())

l = len(a) & ~1
for i in range(0, l, 4):
    x0 = a[i + 0]
    x1 = a[i + 1]
    x2 = a[i + 2]
    x3 = a[i + 3]
    a[i + 0] = x3
    a[i + 1] = x2
    a[i + 2] = x1
    a[i + 3] = x0

with open(str(output_dir / filename), "wb") as f_out:
    f_out.write(a)
