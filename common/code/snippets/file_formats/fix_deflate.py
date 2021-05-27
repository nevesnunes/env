#!/usr/bin/env python3

# Attempts to correct DEFLATE stream corruption consisting
# of isolated 1 or 2 bytes.
#
# Algorithm:
# - Bruteforce 2 bytes at a time, checking if the decompression
#   result length is larger than the previous.
#
# Example error throwed by `zlib` for this corruption:
# > Error -3 while decompressing data: invalid distance too far back
#
# TODO:
# - Detection of the correct byte value to patch in the stream is verified
#   manually, which only works for plaintext and other partially decodable formats.
#   Given known file type, use `tree-sitter` to sort results by longest recovered AST.

import sys
import zlib

CHUNKSIZE = 2

# −8 to −15: Uses the absolute value of wbits as the window size logarithm.
#            The input must be a raw stream with no header or trailer.
# Reference: https://docs.python.org/3/library/zlib.html#decompress-wbits
WSIZE_LOG = -15


def fix(data, i, best_len=0):
    o = b""
    initial_len = best_len
    for wi in range(-2, CHUNKSIZE * 2, 1):
        prev_c = data[i + wi]
        for k in range(0xFF):
            data[i + wi] = k

            prev_c2 = data[i + wi + 1]
            for k2 in range(0xFF):
                data[i + wi + 1] = k2

                o = decompress(data)
                if len(o) > initial_len:
                    print(i + wi, k, k2, len(o))
                    best_len = len(o)
                    print(o)

            data[i + wi + 1] = prev_c2
        data[i + wi] = prev_c
    print(o)


def decompress(data):
    decompress_obj = zlib.decompressobj(WSIZE_LOG)
    o = b""
    for i in range(0, len(data) // CHUNKSIZE + 1, 1):
        buffer = data[CHUNKSIZE * i : CHUNKSIZE * (i + 1)]
        try:
            o += decompress_obj.decompress(buffer)
        except:
            return o
    return o


if __name__ == "__main__":
    data = bytearray(open(sys.argv[1], "rb").read())
    decompress_obj = zlib.decompressobj(WSIZE_LOG)
    o = b""
    for i in range(0, len(data) // CHUNKSIZE + 1, 1):
        buffer = data[CHUNKSIZE * i : CHUNKSIZE * (i + 1)]
        try:
            o += decompress_obj.decompress(buffer)
        except Exception as e:
            print(e, file=sys.stderr)
            print(i, data[i], len(o))
            print(o)
            fix(data[: CHUNKSIZE * (i + 4)], CHUNKSIZE * i, len(o))
            exit(123)
    sys.stdout.buffer.write(o)
