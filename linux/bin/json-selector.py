#!/usr/bin/env python3

import json
import sys

json_data = open(sys.argv[1])
data = json.load(json_data)
element = data
for i in sys.argv[2:]:
    try:
        i = int(i)
    except:
        pass
    element = element[i]
print(json.dumps(element))
