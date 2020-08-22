#!/usr/bin/env python2

from pwn import *
import os

r = remote("misc.chal.csaw.io", 9002)

while True:
    try:
        data = r.recvuntil("equal?: ")
        line = [line for line in data.splitlines() if "=" in line][0]
        print "\n" + line
        out = os.popen("sage -c \"var('X'); print solve([" + line.replace("=", "==") + "], X)\"").read()
        answer = out.split("== ")[1].split("\n")[0]
        print answer
        if "/" in answer: # Sage does not simplify, so python will do it ! :)
            answer = eval(answer.replace("/", "/float(") + ")")
            print answer
        r.sendline(str(answer))
    except:
        print "out", out # In case of failure, please tell us why...
        r.interactive()
