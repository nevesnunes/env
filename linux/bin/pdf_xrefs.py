#!/usr/bin/env python3

import re
import sys


def natural_sort_key(s, _re=re.compile(r"(\d+)")):
    return [int(t) if i & 1 else t.lower() for i, t in enumerate(_re.split(str(s[1], 'latin-1')))]


pdf = open(sys.argv[1], "rb").read()
stream = re.compile(b"[0-9]+ [0-9]+ obj")
matches = []
for match in re.finditer(stream, pdf):
    matches.append([match.start(), match.group(0)])
matches.sort(key=natural_sort_key)
for match in matches:
    print(f"{match[0]:010d} {match[1].decode('latin-1')}")
print()
print("0000000000 65535 f")
for match in matches:
    print(f"{match[0]:010d} 00000 n")
