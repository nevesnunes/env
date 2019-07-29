#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

# ' > '.join(str(x.name) + ':nth-child({})'.format(x.parent.index(x)) for x in reversed(list(tr[0].parents)[:-1]))

import sys
from bs4 import BeautifulSoup

with open(sys.argv[1]) as f:
    soup = BeautifulSoup(f.read(), 'html.parser')
    tr = soup.find_all('tr', recursive=True)
    import ipdb
    ipdb.set_trace()
