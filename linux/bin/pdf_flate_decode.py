#!/usr/bin/env python3

import re
import sys
import zlib

pdf = open(sys.argv[1], "rb").read()
stream = re.compile(b".*?FlateDecode.*?stream(.*?)endstream", re.S)
for s in re.findall(stream, pdf):
    s = s.strip(b"\r\n")
    try:
        sys.stdout.buffer.write(zlib.decompress(s).decode("latin-1"))
        sys.stdout.buffer.flush()
    except Exception as e:
        print(e, sys.stderr)
