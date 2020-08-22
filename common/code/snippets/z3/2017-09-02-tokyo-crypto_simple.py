#!/usr/bin/env python3

import z3


def read_data():
    return bytes.fromhex("7c153a474b6a2d3f7d3f7328703e6c2d243a083e2e773c45547748667c1511333f4f745e")


def decryptor():
    data = read_data()
    s = z3.Solver()
    flag = [z3.Int("flag_" + str(i)) for i in range(len(data) - 15)]
    key = [z3.Int("key_" + str(i)) for i in range(13)]
    pipe = z3.Int("pipe")
    s.add(pipe == ord("|"))
    for var in flag:
        s.add(var < 128)
        s.add(var >= 0)
    for i, c in enumerate("TWCTF{"):
        s.add(flag[i] == ord(c))
    for var in key:
        s.add(var < 128)
        s.add(var >= 0)
    message = flag + [pipe] + key
    for i in range(1, len(data)):
        index = i - 1
        byte = data[i]
        s.add((message[index] + key[index % 13] + data[index]) % 128 == byte)
    print(s.__repr__())
    print(s.check())
    print(s.model())
    print("".join([chr(int(str(s.model()[var]))) for var in message]))

decryptor()
