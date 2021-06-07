#!/usr/bin/env python3

print("".join([chr(0x5f ^ x) for x in bytearray(b"\x41\x41\x41\x41")]))
