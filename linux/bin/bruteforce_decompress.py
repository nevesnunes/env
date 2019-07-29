#!/usr/bin/env python3

from array import array
import sys
import zlib

with open(sys.argv[1], 'rb') as f:
    data = array('B', f.read())
    total_len = len(data)
    best_count = 0
    best_wbits = 0
    best_seek = 0
    best_len = 0
    for len_i in range(0, 5):
        for s in range(0, total_len - len_i):
            f.seek(s)
            sliced_data = data[s:total_len - len_i - s]
            for i in range(-15, 64):
                try:
                    c = zlib.decompress(sliced_data, wbits=i)
                    if len(c) < 5:
                        continue
                    if len(c) > best_count:
                        best_count = len(c)
                        best_wbits = i
                        best_seek = s
                        best_len = len_i
                        print("count:", len(c), "wbits:", i)
                except Exception as e:
                    pass
    print("count:", best_count, "wbits:", best_wbits, "seek:", best_seek, "len:", best_len)
    sliced_data = data[best_seek:total_len - best_len - best_seek]
    c = zlib.decompress(sliced_data, wbits=best_wbits)
    try:
        print(c.decode())
    except Exception as e:
        print(c)
