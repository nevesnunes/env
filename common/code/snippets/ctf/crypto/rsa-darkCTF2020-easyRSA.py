#!/usr/bin/env python3

# Assuming the N to be a big 2048-bit number (general format) and my plaintext (flag) to be relatively small it's clear that (pt ^ e) < N
# This is the vulnerabilty as a mod b = a when a < b so ct = (pt ^ e) mod N becomes equivalent to ct = (pt ^ e).

from Crypto.Util.number import long_to_bytes
import gmpy2

ct = 70415348471515884675510268802189400768477829374583037309996882626710413688161405504039679028278362475978212535629814001515318823882546599246773409243791879010863589636128956717823438704956995941
e = 3

# Calculating e-th root of ciphertext
pt = gmpy2.iroot(ct, e)[0]
print("Flag is : " + str(long_to_bytes(pt).decode()))
