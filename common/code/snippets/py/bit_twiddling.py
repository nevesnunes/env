#!/usr/bin/env python3

def i8(n):
    return ((n & 0xff) ^ 0x80) - 0x80

def i16(n):
    return ((n & 0xffff) ^ 0x8000) - 0x8000

def i24(n):
    return ((n & 0xffffff) ^ 0x800000) - 0x800000

def i32(n):
    return ((n & 0xffffffff) ^ 0x80000000) - 0x80000000

def i64(n):
    return ((n & 0xffffffffffffffff) ^ 0x8000000000000000) - 0x8000000000000000
