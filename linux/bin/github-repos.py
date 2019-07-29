#!/usr/bin/env python2
# -*- encoding: utf-8 -*-

from bs4 import BeautifulSoup as BS

import sys

if __name__ == "__main__":
    with open(sys.argv[1]) as base_file:
        bs = BS(base_file, 'html.parser')
        for block in bs.find(id='code_search_results').find_all(class_='d-inline-block'):
            for link in block.find_all('a', class_='text-bold', href=True):
                (user, repo) = link['href'].split('/')[1:]
                print('git clone https://github.com' + link['href'] + ' ' + user + '_' + repo)
