#!/usr/bin/env python2
# -*- encoding: utf-8 -*-

import base64
import sys

if __name__ == "__main__":
    contents = ''
    with open(sys.argv[1], "rb") as f:
        contents = base64.b64encode(f.read())
    if len(sys.argv) > 2:
        with open(sys.argv[2], "w") as f:
            f.write(contents)
    else:
        print contents
