#!/usr/bin/env python3

import sys
import struct


def chunks(lst, n):
    """Expand successive n-sized chunks from lst."""
    return [lst[i - n : i] for i in range(n, len(lst) + n, n)]


def truncate(data, at, size):
    data_chunks = chunks(bin(v)[2:], 8)
    print(data_chunks)

    data_chunks_truncated = []
    x = None
    y_size = size
    has_trailing_bits = False
    for y in data_chunks:
        if not x:
            x = y
            continue
        x = (x[:at] + x[at + size:] + y[:y_size]).ljust(8, "0")
        data_chunks_truncated.append(x)

        has_trailing_bits = len(y[y_size:]) > 0
        x = (y[y_size:]).ljust(8, "0")

        at = 8 - size
    if has_trailing_bits:
        data_chunks_truncated.append(x)

    return data_chunks_truncated


if __name__ == "__main__":
    v = int(sys.argv[1], 0)
    at = int(sys.argv[2], 0)
    size = int(sys.argv[3], 0)
    print(truncate(v, at, size))
