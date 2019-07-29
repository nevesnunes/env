#!/usr/bin/env python2
# -*- encoding: utf-8 -*-

import csv
import sys
from BeautifulSoup import BeautifulSoup
from urllib2 import urlopen

try:
    f = urlopen(sys.argv[1])
except urllib2.HTTPError:
    f = open(sys.argv[1])
soup = BeautifulSoup(f)
tables = soup.findAll('table')
idx = 0
for table in tables:
    headers = [header.text for header in table.findAll('th')]
    rows = []
    for row in table.findAll('tr'):
        rows.append([val.text.encode('utf8') for val in row.findAll('td')])
    with open('out' + str(idx) + '.csv', 'wb') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(row for row in rows if row)
