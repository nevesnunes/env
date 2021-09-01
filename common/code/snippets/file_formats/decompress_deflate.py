#!/usr/bin/env python3

import sys
import zlib

CHUNKSIZE = 2

# −8 to −15: Uses the absolute value of wbits as the window size logarithm.
#            The input must be a raw stream with no header or trailer.
# Reference: https://docs.python.org/3/library/zlib.html#decompress-wbits
WSIZE_LOG = -15


if __name__ == "__main__":
    data = bytearray(open(sys.argv[1], "rb").read())
    end_i = float("inf")
    if len(sys.argv) > 2:
        end_i = int(sys.argv[2], 0)

    decompress_obj = zlib.decompressobj(WSIZE_LOG)
    o = b""
    for i in range(0, len(data) // CHUNKSIZE + 1, 1):
        if i > end_i:
            print(f"Break: i > end_i")
            break
        buffer = data[CHUNKSIZE * i : CHUNKSIZE * (i + 1)]
        try:
            o += decompress_obj.decompress(buffer)
        except Exception as e:
            print(f"Break: {e}")
            break
    print(f"Attempted i: {hex(i)}")
    sys.stdout.buffer.write(o)
