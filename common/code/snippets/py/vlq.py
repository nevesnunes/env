#!/usr/bin/env python3

def vlq(n):
    v = n & 0x7f
    if (n & 0x8000 == 0x8000):
        v += ((n & 0x7f00) >> 8) * 0x80
    if (n & 0x800000 == 0x800000):
        v += ((n & 0x7f0000) >> 8 * 2) * 0x80 * 0x80
    if (n & 0x80000000 == 0x80000000):
        v += ((n & 0x7f000000) >> 8 * 3) * 0x80 * 0x80 * 0x80
    return v


print(hex(vlq(0x7f)))
print(hex(vlq(0x8100)))
print(hex(vlq(0xc000)))
print(hex(vlq(0xff7f)))
print(hex(vlq(0x818000)))
print(hex(vlq(0xc08000)))
print(hex(vlq(0xffff7f)))
print(hex(vlq(0x81808000)))
print(hex(vlq(0xc0808000)))
print(hex(vlq(0xffffff7f)))
