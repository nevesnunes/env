#!/usr/bin/env python3

import re
import sys

filename = sys.argv[1]
pattern = re.escape(sys.argv[2])
with open(filename, 'r') as f:
    match_count = 0
    prev_line = ''
    for i, line in enumerate(f.readlines()):
        if len(re.findall(pattern, line)) > 0:
            match_count += 1
        else:
            match_count = 0
        if match_count > 1:
            print(f"{filename}-{i-1}-{prev_line.rstrip()}")
            print(f"{filename}:{i}:{line.rstrip()}")
            match_count = 0
        prev_line = line
