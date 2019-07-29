#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import codecs
import sys

e = 'cp1252'
if len(sys.argv) > 2:
    e = sys.argv[2]
try:
    f = codecs.open(sys.argv[1], encoding=e)
    for line in f:
        pass
except UnicodeDecodeError:
    print("Error: " + sys.argv[1])
