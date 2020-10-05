#!/usr/bin/env python3

# Reference:
# - https://medium.com/@apogiatzis/tuctf-2018-xorient-write-up-xor-basics-d0c582a3d522

import sys


def xor(message, key):
    o = ""
    for i in range(len(message)):
        o += chr(message[i] ^ ord(key[i % len(key)]))
    return o


# Accept either file or bytes as arguments
key = None
try:
    with open(sys.argv[1], "rb") as f:
        key = f.read().strip()
except Exception:
    key = sys.argv[1].encode(sys.getfilesystemencoding(), "surrogateescape")
message = None
try:
    with open(sys.argv[2], "rb") as f:
        message = f.read().strip()
except Exception:
    message = sys.argv[2].encode(sys.getfilesystemencoding(), "surrogateescape")

print(xor(message, key))
