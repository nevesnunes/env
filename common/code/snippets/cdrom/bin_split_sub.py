#!/usr/bin/env python3

"""
Takes a .bin that includes subchannel data,
outputs a .sub file with packed bits (like CloneCD's format),
and another .bin without subchannel data.
"""

import os
import sys

SECTOR_SIZE = 0x990
SECTOR_START_SIGNATURE = b"\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00"

input_bin = sys.argv[1]
output_bin = f"{'.'.join(input_bin.split('.')[:-1])}.nosub.bin"
output_sub = f"{'.'.join(input_bin.split('.')[:-1])}.sub"
with open(input_bin, "rb") as f_in_bin, open(output_bin, "wb") as f_out_bin, open(output_sub, "wb") as f_out_sub:
    start_offset = f_in_bin.tell()
    size = f_in_bin.seek(0, os.SEEK_END)
    f_in_bin.seek(start_offset)
    if size % SECTOR_SIZE != 0:
        raise RuntimeError("Input file is not 2448 byte aligned.")

    num_sectors = size // SECTOR_SIZE
    for i in range(num_sectors):
        sector = f_in_bin.read(0x930)
        if sector[0:0x0C] != SECTOR_START_SIGNATURE:
            raise RuntimeError(f"Sector {i} (offset 0x{hex(i * SECTOR_SIZE)}) start signature not found.")
        f_out_bin.write(sector)

        sub_packed = [0] * 0x60
        sub_interleaved = f_in_bin.read(0x60)
        for byte_i in range(0x60):
            interleaved_byte = sub_interleaved[byte_i]
            for bit_i in range(8):
                bit = (interleaved_byte & (1 << bit_i)) >> bit_i
                channel_chunk = (7 - bit_i) * (0x60 // 8)
                channel_offset = channel_chunk + (byte_i // 8)
                sub_packed[channel_offset] |= (bit << (7 - (byte_i % 8)))
        f_out_sub.write(bytearray(sub_packed))
