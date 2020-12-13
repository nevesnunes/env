#!/usr/bin/env python3

# Usage:
# ./lsb.py foo.png RGBRGB

# Validation:
# - StegSolve > `Data extract`
# - Compare against bits in first 8 pixel components (~= 3 pixels):
#     - [str(bin(x))[2:].zfill(8) for i in range(3) for x in list(data[i])]

import sys
from PIL import Image
from itertools import cycle

image = Image.open(sys.argv[1].strip())
data = list(image.getdata())
order = cycle(sys.argv[2].strip())
bit_i = 0
message = []
for rgb in data:
    for i in range(3):
        # https://stackoverflow.com/questions/12173774/how-to-modify-bits-in-an-integer
        channel = next(order)
        if channel == "R":
            message.append(1 if rgb[0] & 1 << bit_i else 0)
        elif channel == "G":
            message.append(1 if rgb[1] & 1 << bit_i else 0)
        elif channel == "B":
            message.append(1 if rgb[2] & 1 << bit_i else 0)
        else:
            raise RuntimeError(f"Unexpected channel: {channel}")

out = []
for i in range(0, len(message), 8):
    out.append(chr(int("".join([str(x) for x in message[i : i + 8]]), 2)))
sys.stdout.buffer.write(bytes("".join(out), "latin-1"))
