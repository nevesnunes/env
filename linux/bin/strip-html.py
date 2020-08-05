#!/usr/bin/env python3

# TODO: join hrefs with text contents

from bs4 import BeautifulSoup
from io import StringIO
import re
import sys

table_separator = ' | '

for arg in sys.argv[1:]:
    if arg == '--csv':
        table_separator = ','
    else:
        filename = arg

with open(filename, 'r') as f:
    soup = BeautifulSoup(f.read(), features='html.parser')

    # remove non-content elements
    ignored_elements = soup.findAll(['head', 'script', 'style'])
    for match in ignored_elements:
        match.decompose()

    # sort table rows, join cells into single cell
    for elem_table in soup.find_all('table'):
        rows = [x.extract() for x in elem_table.find_all('tr')]
        rows_filtered = [x for x in rows if x.find('td')]
        for row in rows_filtered:
            for x in row.find_all('td'):
                if len(x.get_text(strip=True)) == 0:
                    x.extract()
        rows_filtered.sort(key=lambda x: [x.get_text() for x in x.find_all('td')])
        for row in rows_filtered:
            row_tds = row.find_all('td')
            row_string = table_separator.join([x.get_text(strip=True) for x in row_tds])
            for x in row_tds:
                x.extract()
            new_td = soup.new_tag('td')
            new_td.string = row_string
            row.append(new_td)
            elem_table.append(row)

    # trim strings
    for x in soup.find_all():
        if len(x.get_text(strip=True)) == 0:
            x.extract()
        elif x.string:
            x_string = x.get_text()
            x_string = re.sub(r'[ \t\f\v\r\n]+', ' ', x_string, re.MULTILINE)
            x.string.replace_with(x_string.strip() + '\n')

    for line in StringIO(soup.get_text()):
        stripped_line = line.strip()
        if len(stripped_line) == 0:
            continue
        print(stripped_line)
