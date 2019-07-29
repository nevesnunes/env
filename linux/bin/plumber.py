#!/usr/bin/env python3

import re

import sys

maybe_url = str(sys.argv[1:])
url_regex = r'(https?://[-A-Za-z0-9+&@#/%?=~_()|!:,.;]*[-A-Za-z0-9+&@#/%=~_()|])'

# Remove enclosing braces
if (maybe_url.startswith("(")) and (maybe_url.endswith(")")):
    maybe_url = maybe_url[1:-1]

# Remove trailing brace
if not (maybe_url.startswith("(")) and (maybe_url.endswith(")")):
    maybe_url = maybe_url[:-1]

print(re.findall(url_regex, maybe_url))
