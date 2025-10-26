#!/usr/bin/env python3

import argparse
import os
import re

DEBUG = bool(os.environ.get("DEBUG"))


def log(text):
    if DEBUG:
        print(text)


parser = argparse.ArgumentParser()
parser.add_argument("-f", "--files", nargs="+", help="Memory dumps", required=True)
parser.add_argument("-p", "--pattern", nargs="+", help="Byte patterns in hex", required=True)
parser.add_argument("-i", "--indexes", nargs="+", help="Indexes to match a file to a searched pattern (e.g. `-i 2 -1` will search 1st pattern on 3rd file, then 2nd pattern on last file, remaining files must have distinct patterns")
args = parser.parse_args()

dumps = []
for filename in args.files:
    with open(filename, "rb") as f:
        dumps.append(f.read())

indexes = set()
if args.indexes:
    indexes = set([int(i) for i in args.indexes])

target_count = len(args.files)
count_by_addresses = {}
for i, p in enumerate(args.pattern):
    r = re.compile(re.escape(bytes.fromhex(p)))
    for d_i, d in enumerate(dumps):
        log(f"  find | {d_i} {i} {p}")
        for match_pair in [[m.start(), m.end()] for m in r.finditer(d)]:
            match_start = match_pair[0]
            if match_start not in count_by_addresses:
                count_by_addresses[match_start] = 0

            if len(indexes) > 0:
                if d_i not in indexes:
                    count_by_addresses[match_start] = -1
                    log(f"    -1 | {d_i} {i} {p} @ {hex(match_start)}")
                else:
                    count_by_addresses[match_start] += 1
                    log(f"    +1 | {d_i} {i} {p} @ {hex(match_start)}")
            else:
                if count_by_addresses[match_start] != i:
                    count_by_addresses[match_start] = -1
                    log(f"    -1 | {d_i} {i} {p} @ {hex(match_start)}")
                else:
                    count_by_addresses[match_start] += 1
                    log(f"    +1 | {d_i} {i} {p} @ {hex(match_start)}")

log(f"counts | {count_by_addresses}")

matched_count_by_addresses = []
if len(indexes) > 0:
    matched_count_by_addresses.extend(
        filter(
            lambda x: count_by_addresses[x[0]] == len(indexes),
            count_by_addresses.items(),
        )
    )
else:
    matched_count_by_addresses.extend(
        filter(
            lambda x: count_by_addresses[x[0]] == target_count,
            count_by_addresses.items(),
        )
    )

for match in matched_count_by_addresses:
    print(hex(match[0]))
