#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import csv
import os
import pprint
import sqlite3
import sys

def explore(filename, encoding):
    with open(filename, 'r', encoding=encoding) as source:
        csv_reader = csv.DictReader(source, delimiter=',', quotechar='"')
        columns = csv_reader.fieldnames

        conn = sqlite3.connect(':memory:')
        curs = conn.cursor()
        sql_create = 'create table main (' + \
                ','.join('"' + column + '"' + ' text' for column in columns) + \
                ')'
        conn.execute(sql_create)

        sql_inserts = 'insert into main (' + \
                ','.join('"' + column + '"' for column in columns) + \
                ') values ({})'.format(','.join('?' for column in columns))
        for row in csv_reader:
            conn.execute(sql_inserts, list(row.values()))

        sql_counts = 'select ' + \
                ','.join('\'{0}:{1}\', count(distinct "{1}")'.format(i, column)
                        for i, column in enumerate(columns)) + \
                'from main;'
        curs.execute(sql_counts)
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(curs.fetchall())

filename = sys.argv[1]
encoding = 'utf-8'
try:
    with open(filename, 'r') as source:
        source.read()
except UnicodeDecodeError:
    encoding = 'iso-8859-1'
explore(filename, encoding)
