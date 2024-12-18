#!/usr/bin/env python3

# Reference:
# - https://medium.com/@apogiatzis/tuctf-2018-xorient-write-up-xor-basics-d0c582a3d522

import string
import sys

printable_ascii = [ord(i) if ord(i) < 128 else None for i in list(string.printable)]


def candidate_keys(message, key):
    candidates = []
    for k in range(len(message) - len(key)):
        o = []
        for i in range(len(key)):
            c = message[(i + k) % len(message)] ^ key[i % len(key)]
            o.append(c)
        candidates.append(o)
    return candidates


def xor(message, key):
    max_matched_length = 0
    picked_candidate = None
    picked_i = 0
    for k in range(len(key)):
        matched_length = 0
        o = []
        for i in range(len(message)):
            c = message[(i + k) % len(message)] ^ key[i % len(key)]
            o.append(c)
            if c in printable_ascii:
                matched_length += 1
        print(f"Decrypted {matched_length} printable chars with key at index {k}", file=sys.stderr)
        if matched_length > max_matched_length:
            print("Best so far!", file=sys.stderr)
            max_matched_length = matched_length
            picked_candidate = o
            picked_i = i
    print(f"Picked candidate with key at index = {picked_i}", file=sys.stderr)
    sys.stdout.buffer.write(bytes(picked_candidate))
    sys.stdout.buffer.write(b'\n')


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

for candidate in candidate_keys(message, key):
    xor(message, candidate)
