#!/usr/bin/env python3


def twos(val, bits):
    if (val & (1 << (bits - 1))) != 0:
        val = val - (1 << bits)
    return val


def i8(n):
    return ((n & 0xFF) ^ 0x80) - 0x80


def i16(n):
    return ((n & 0xFFFF) ^ 0x8000) - 0x8000


def i24(n):
    return ((n & 0xFFFFFF) ^ 0x800000) - 0x800000


def i32(n):
    return ((n & 0xFFFFFFFF) ^ 0x80000000) - 0x80000000


def i64(n):
    return ((n & 0xFFFFFFFFFFFFFFFF) ^ 0x8000000000000000) - 0x8000000000000000


def u8(n):
    return n & 0xFF


def u16(n):
    return n & 0xFFFF


def u24(n):
    return n & 0xFFFFFF


def u32(n):
    return n & 0xFFFFFFFF


def u64(n):
    return n & 0xFFFFFFFFFFFFFFFF


def sub(n, c, max_bits=64):
    mask = (1 << max_bits) - 1
    return (n - c) & mask


def ror(x, r, max_bits=64):
    mask = (1 << max_bits) - 1
    return ((x >> r % max_bits) | (x << (max_bits - r % max_bits))) & mask


def rol(x, r, max_bits=64):
    mask = (1 << max_bits) - 1
    return ((x << r % max_bits) | (x >> (max_bits - r % max_bits))) & mask


def rol_alt(n, r, max_bits=64):
    return (n << r % max_bits) & (2**max_bits - 1) | (
        (n & (2**max_bits - 1)) >> (max_bits - (r % max_bits))
    )


def ror_alt(n, r, max_bits=64):
    return ((n & (2**max_bits - 1)) >> r % max_bits) | (
        n << (max_bits - (r % max_bits)) & (2**max_bits - 1)
    )
