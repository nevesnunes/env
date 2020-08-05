#!/usr/bin/env python3

import binascii
import re
import sys


hex_bytes_clean = "".join(sys.argv[2].split())
raw_bytes = binascii.a2b_hex(hex_bytes_clean)
with open(sys.argv[1], "rb") as f:
    for x in re.finditer(raw_bytes, f.read()):
        print(hex(x.start()))
