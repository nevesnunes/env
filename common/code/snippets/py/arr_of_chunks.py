#!/usr/bin/env python3

n = 2
l = "foo"
chunks = [l[i - n : i] for i in range(n, len(l) + n, n)]
print(chunks)
