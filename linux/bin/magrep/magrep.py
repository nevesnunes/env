#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import itertools
import re
import sys

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: {0} file regex [max_lines]".format(sys.argv[0]))
        exit(1)

    filename = sys.argv[1]
    needle = sys.argv[2]
    max_lines = -1
    if len(sys.argv) > 3:
        max_lines = int(sys.argv[3])

    with open(filename) as data:
        processed_needle = needle
        re_parts = re.compile(r"[^\.\*]+\.\*[^\.\*]+")
        if re_parts.match(needle):
            # Match regardless of part order
            parts = needle.split('.*')
            needle = "|".join(
                '.*'.join(x)
                for x in list(
                    itertools.permutations(
                        parts,
                        len(parts))))

            # Only get smallest matches
            parts = needle.split('.*')
            processed_needle = ''
            for i, part in enumerate(parts):
                processed_needle += part
                if i != len(parts) - 1:
                    processed_needle += "((?!{0}).)*?".format(part)

        re_needle = re.compile(
            processed_needle,
            re.DOTALL | re.I | re.MULTILINE)
        text = data.read()
        for match in re_needle.finditer(text):
            start_line = text[:match.start()].count('\n') + 1
            end_line = start_line + text[match.start():match.end()].count('\n')
            if max_lines > -1 and end_line - start_line + 1 > max_lines:
                continue

            match_lines = match.group().split('\n')
            for match_line in match_lines:
                print("{0}:{1}-{2}:{3}".format(filename,
                                               start_line, end_line, match_line))
                start_line += 1
