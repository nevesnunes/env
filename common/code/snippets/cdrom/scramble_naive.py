#!/usr/bin/env python3

"""
Generates the sequence for CD scrambler. Too much boilerplate, see other approaches...
"""


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


def from_le(lst, n=4):
    """Reorder bytes by switching endianess."""
    lst_be = []
    for chunk in chunks(lst, n):
        lst_be.extend(chunk[::-1])
    return lst_be


def set_bit(v, index, x):
    """Set the index:th bit of v to 1 if x is truthy, else to 0, and return the new value."""
    mask = 1 << index  # Compute mask, an integer with just bit 'index' set.
    v &= ~mask  # Clear the bit indicated by the mask (if x is False)
    if x:
        v |= mask  # If x was True, set the bit indicated by the mask.
    return v  # Return the result, we're done.


def scramble(data):
    new_c = 0x8001
    new_data = bytes(bin(new_c)[2:].zfill(16), encoding="ascii")
    for c in data:
        for b in bin(c)[2:].zfill(16)[::-1]:
            b_add_mod2 = (new_c & 1) ^ ((new_c & 2) >> 1)
            new_c = set_bit(new_c, 15, b_add_mod2)
            new_c >>= 1
        new_data += bytes(bin(new_c)[2:].zfill(16), encoding="ascii")
        print(bin(new_c)[2:].zfill(16), hex(new_c))
    for c, new_c in zip(data, from_le(list(chunks(new_data[4 * 8 :], 8)), 2)):
        v = 0
        for b in new_c:
            v <<= 1
            v |= int(chr(b), 2)
        print(hex(v), hex(c), hex(v ^ c))


if __name__ == "__main__":
    data_0 = b"\x00\xD7\xFF\xE1\x7F\xF7\x9F\xF9\x57\xFD\x01\x81"
    scramble(data_0)
