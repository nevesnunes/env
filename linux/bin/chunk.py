#!/usr/bin/env python3

import binascii
import sys

with open(sys.argv[1], "rb") as f:
    start_address = int(sys.argv[2], 16)
    end_address = int(sys.argv[3], 16)
    chunk_length = end_address - start_address
    f.seek(start_address)
    data = f.read(chunk_length)
    sys.stdout.buffer.write(data)
