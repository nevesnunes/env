#!/usr/bin/env python3

"""
Generates the sequence for CD scrambler. Uses the shift register method, as specified in ECMA-130 Annex B.

Adapted from: "CD Cracking Uncovered: Protection against Unsactioned CD Copying" By Kris Kaspersky
"""


def update(reg):
    for i in range(8):
        hibit = ((reg & 1) ^ ((reg & 2) >> 1)) << 15
        reg = (hibit | reg) >> 1
    return reg


def scramble(data):
    reg = 1
    for i in range(4):
        reg = update(reg)
    for i in range(len(data)):
        data[i] = data[i] ^ (reg & 0xFF)
        reg = update(reg)
    return data


if __name__ == "__main__":
    # Pattern at offset 0 after sync block in sector
    data = list(b"\x00\xD7\xFF\xE1\x7F\xF7\x9F\xF9\x57\xFD\x01\x81")
    data = scramble(data)

    # b'\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00'
    print(bytes(data))
