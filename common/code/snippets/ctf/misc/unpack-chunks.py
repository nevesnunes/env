from pwn import *

data = open('re2', 'rb').read()

str_data = data[0xe58:0xecf]
offset_data = data[0x20c0:0x213c]

# Splits data into many 32 bit chunks
offsets = unpack_many(offset_data, 32)

flag = ''
for x in offsets:
    flag += str_data[x]

print flag
