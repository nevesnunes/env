#!/usr/bin/env python2
# -*- encoding: utf-8 -*-

import chardet
import re
import os

for n in os.listdir('.'):
    encoding = chardet.detect(n)['encoding']
    if re.match(r"ascii|utf", encoding):
        continue
    print '%s: %s (%s)' % (n, chardet.detect(n)['encoding'], chardet.detect(n)['confidence'])
