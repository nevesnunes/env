#!/usr/bin/env python3

"""
Generates the sequence for CD scrambler. Uses the pre-computed lookup table method, as disassembled from Clone CD's ElbyECC.dll#RawScrambleSector function.

Adapted from: "CD Cracking Uncovered: Protection against Unsactioned CD Copying" By Kris Kaspersky
"""

SYNC_BLOCK_LEN = 12


# Check fragment of the real scrambling sequence:
# 0x8001,0x6000,0x2800,0x1e00,0x0880,0x0660,0x02a8,0x81fe,0x6080,0x2860,0x1e28,
# 0x889e,0x6668,0xaaae,0x7ffc,0xe001,0x4800,0x3600,0x1680,0x0ee0,0x04c8,0x8356,
# 0xe17e,0x48e0,0x3648,0x96b6,0xeef6,0xccc6,0xd552,0x9ffd,0xa801,0x7e00,0x2080,
def init_scrambler_table():
    scrambler_table = b"\x80\x01"
    reg = 0x8001
    # The first element of the scrambling sequence
    for a in range(1, 1170):  # The scrambled sector part length in words
        # Modulo - 2 addition with shift
        tmp = reg >> 1
        tmp = reg ^ tmp
        reg = tmp >> 1

        # Processing polynomial x ^ 15 + x + 1, e.g., 1 << 15 + 1 << 1 + 1 << 0
        if reg & 1 << 1:
            reg = reg ^ (1 << 15)
        if reg & 1 << 0:
            reg = reg ^ ((1 << 15) | (1 << 14))

        scrambler_table += bytes([reg & 0xFF])
        scrambler_table += bytes([(reg >> 8) & 0xFF])

    return scrambler_table


if __name__ == "__main__":
    scrambler_table = init_scrambler_table()

    # Pattern at offset 0 after sync block in sector
    data = list(b"\x00\xD7\xFF\xE1\x7F\xF7\x9F\xF9\x57\xFD\x01\x81")
    for a in range(SYNC_BLOCK_LEN):
        data[a] ^= scrambler_table[a + 4]

    # b'\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00'
    print(bytes(data))
