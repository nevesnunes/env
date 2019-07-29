#!/usr/bin/env python

import sys

from bs4 import BeautifulSoup

filename = 'out'
suffix = '-'
suffix_count = 0
css = {
    'font-family': 'sans-serif',
    'font-size': 14
}

with open(sys.argv[1]) as f_in:
    page = BeautifulSoup(f_in, 'lxml')
    page_elements = page.find_all('svg')
    for element in page_elements:
        for k, v in css.iteritems():
            element[k] = v
        with open(filename + suffix + str(suffix_count) + '.svg', 'w+') as f_out:
            f_out.write(str(element))
            suffix_count += 1
