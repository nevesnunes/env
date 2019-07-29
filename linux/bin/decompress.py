#!/usr/bin/env python3

from array import array
import sys
import zlib

with open(sys.argv[1], 'rb') as f:
    data = array('B', f.read())
    c = zlib.decompress(data, wbits=-15)
    try:
        print(c.decode())
    except Exception as e:
        print(c)
