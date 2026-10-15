#!/usr/bin/env python3

import sys


def _crc16_initial(c):
    crc = 0
    c = c << 8
    for _ in range(8):
        if (crc ^ c) & 0x8000:
            crc = (crc << 1) ^ 0x1021
        else:
            crc = crc << 1
        c = c << 1
    return crc


_crc16_tab = [_crc16_initial(i) for i in range(256)]


def crc16(data: bytearray):
    crc = 0xFFFF
    for c in data:
        tmp = (crc >> 8) ^ c
        crc = (crc << 8) ^ _crc16_tab[tmp & 0xFF]
        crc = crc & 0xFFFF
    return crc


# SECTOR_SIZE = 0x100
# NUM_SECTORS = 16
# SECTOR_SIZE = 0x200
# NUM_SECTORS = 18
SECTOR_SIZE = 0x200
NUM_SECTORS = 9

with open(sys.argv[1], "rb") as f:
    data = f.read()
i = 0
for track in range(80):
    for head in range(2):
        for sector in range(NUM_SECTORS):
            crc = crc16(bytearray(b"\xa1\xa1\xa1\xfb" + data[i : i + SECTOR_SIZE]))
            print(f"Track {track} Head {head} Sector {sector} [{i:06x}..{i+SECTOR_SIZE:06x}] CRC = {crc:04x}")
            i += SECTOR_SIZE
