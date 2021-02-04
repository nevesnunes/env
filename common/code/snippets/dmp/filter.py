#!/usr/bin/env python3

# References:
# - https://github.com/google/diff-match-patch/wiki/Line-or-Word-Diffs

import diff_match_patch
import sys
import re


def unified_format(diff):
    changes = []
    change_symbol = None
    has_changes = False
    for pair in diff:
        if pair[0] == -1:
            change_symbol = "-"
            has_changes = True
        elif pair[0] == 1:
            change_symbol = "+"
            has_changes = True
        elif pair[0] == 0:
            change_symbol = " "

        change = pair[1]
        if not change.endswith("\n"):
            change += "\n"
        change = re.sub(r"([^\n]+)\n", f"{change_symbol}\\1\n", change, re.MULTILINE)
        changes.append(change)
    if has_changes:
        return changes


patterns = []
with open(sys.argv[1], "r") as f:
    rules = f.readlines()
    for rule in rules:
        patterns.append(re.compile(rule.strip(), re.IGNORECASE))

with open(sys.argv[2], "r") as f1, open(sys.argv[3], "r") as f2:
    c1 = f1.read()
    c2 = f2.read()

for pattern in patterns:
    c1 = re.sub(pattern, "_", c1.strip(), re.MULTILINE)
    c2 = re.sub(pattern, "_", c2.strip(), re.MULTILINE)

dmp = diff_match_patch.diff_match_patch()
chars_tuple = dmp.diff_linesToChars(c1, c2)
line_text1 = chars_tuple[0]
line_text2 = chars_tuple[1]
line_array = chars_tuple[2]
diffs = dmp.diff_main(line_text1, line_text2, checklines=False)
dmp.diff_charsToLines(diffs, line_array)
print(diffs)
for change in unified_format(diffs):
    print(change, end="")
