#!/usr/bin/python

# V1.0 2007/08/20
# Source code put in public domain by Didier Stevens, no Copyright
# https://DidierStevens.com
# Use at your own risk
#
# History:
#  

import sys

def rol(byte, count):
    while count > 0:
        byte = (byte << 1 | byte >> 7) & 0xFF
        count -= 1
    return byte

def ror(byte, count):
    while count > 0:
        byte = (byte >> 1 | byte << 7) & 0xFF
        count -= 1
    return byte

if len(sys.argv) != 4 and len(sys.argv) != 5:
    print "Usage: translate infile outfile command [script-file]"
    print "  Translate V1.0, use it to translate bytes in a file"
    print "  example: tranlate.py svchost.exe svchost.exe.dec 'byte ^ 0x10'"
    print "  byte is the current byte in the file, 'byte ^ 0x10' does an X0R 0x10"
    print "  extra functions: rol(byte, count) and ror(byte, count)"
    print "  variable position is an index into the input file, starting at 0"
    print "  Source code put in the public domain by Didier Stevens, no Copyright"
    print "  Use at your own risk"
    print "  https://DidierStevens.com"

else:
    infile = open(sys.argv[1], 'rb')
    outfile = open(sys.argv[2], 'wb')
    command = sys.argv[3]
    if (len(sys.argv) == 5):
        execfile(sys.argv[4])
    position = 0
    while True:
        inbyte = infile.read(1)
        if not inbyte:
            break
        byte = ord(inbyte)
        outbyte = eval(command)
        outfile.write(chr(outbyte))
        position += 1
    infile.close()
    outfile.close()

