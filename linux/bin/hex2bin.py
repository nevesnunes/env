#!/usr/bin/env python3

import binascii
import sys

hex_bytes = sys.stdin.buffer.read()
hex_bytes_clean = ''.join(str(hex_bytes, encoding='UTF8').split())
raw_bytes = binascii.a2b_hex(hex_bytes_clean)
sys.stdout.buffer.write(raw_bytes)
