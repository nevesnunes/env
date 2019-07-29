#!/usr/bin/env python3

# Usage:
# set-byte eeprom_bad.bin 0x7D00 0
# set-byte eeprom_bad.bin 1000 0xff

import sys

fileName = sys.argv[1]
offset = int(sys.argv[2], 0)
byte = int(sys.argv[3], 0)

with open(fileName, "r+b") as fh:
    fh.seek(offset)
    fh.write(bytes([byte]))
