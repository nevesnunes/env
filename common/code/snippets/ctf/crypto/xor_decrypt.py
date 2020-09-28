#!/usr/bin/env python3

# Reference:
# - https://medium.com/@apogiatzis/tuctf-2018-xorient-write-up-xor-basics-d0c582a3d522

import sys


def xor(message, key):
    o = ""
    for i in range(len(message)):
        o += chr(ord(message[i]) ^ ord(key[i % len(key)]))
    return o


key = sys.argv[1]
message = None
with open(sys.argv[2], "r") as f:
    message = f.read().strip()

print(xor(message, key))
