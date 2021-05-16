#!/usr/bin/env python3


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


def le(a, n=4):
    """Reorder chars as little-endian n byte sequences."""
    return "".join([x[::-1] for x in chunks(a, n)])
