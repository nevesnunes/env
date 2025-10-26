#!/usr/bin/env python3

import os
import re
import sys

for path in os.scandir():
    if not path.is_dir():
        continue

    old_name = path.name
    new_info = ""

    label_end_pos = 0
    label_match = re.search(r"^\s*(\[[^\]]*\])\s+", old_name)
    if label_match:
        label_end_pos = label_match.end()
        new_info += label_match.group(0).strip()

    date_start_pos = len(old_name)
    date_match = re.search(r"\s*(\[[^\]]*\])\s*$", old_name)
    if date_match:
        date_start_pos = date_match.start()
        if label_match:
            new_info = new_info[:-1] + " - " + date_match.group(0).strip()[1:]
        else:
            new_info += date_match.group(0).strip()

    new_name = old_name[label_end_pos:date_start_pos]
    if new_info:
        new_name += ' ' + new_info
    new_name = re.sub(' – ', ' - ', new_name)
    print(new_name)

    try:
        if old_name != new_name:
            os.rename(old_name, new_name)
    except Exception as e:
        print(e)
