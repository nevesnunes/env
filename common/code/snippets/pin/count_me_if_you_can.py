#!/usr/bin/env python2

import sys
import commands

if __name__ == "__main__":
    pwd  = "________"
    base = 0x2e
    off  = 0x00
    sav  = 0x00
    while pwd.find("Good Password") == -1:
        pwd = pwd[:off] + chr(base) + pwd[off+1:];
        cmd = "./pin -t ./inscount0.so -- ./crackme <<< %s > /dev/null; cat inscount.out" %(pwd)
        res = int(commands.getstatusoutput(cmd)[1].split("Count")[1])
        print "insert('%s') = %d ins" %(pwd, res)
        if sav == 0x00:
            sav = res
        if res - sav > 200:
            off += 1
            if off >= len(pwd):
                break
            base = 0x2d
            sav = 0
        base += 1
        sav = res
    print "The password is %s" %(pwd)
    sys.exit(0)
