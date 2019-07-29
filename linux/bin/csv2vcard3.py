#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import csv
import sys

# Convert a 'comma separated values' file to vcf contact cards

# Usage:
# csv2vcard.py csv_filename

# See:
# https://en.wikipedia.org/wiki/VCard#Properties

def convert(filename, encoding):
    # File format:
    # - Full Name
    # - First Name
    # - Last Name
    # - Extra Name
    # - Telephone
    # - Contact (Personal)
    # - Contact (Home)
    # - Contact (Work)
    # - Fax
    # - E-mail
    # - Address
    # - Notes

    with open(filename, 'r', encoding=encoding) as source:
        reader = csv.reader(source, delimiter=',', quotechar='"')
        with open('ALL.vcf', 'w', encoding=encoding) as vcf:
            for csv_row in reader:
                row = [None] * 100
                for i in range(len(csv_row)):
                    row[i] = csv_row[i].strip()

                # Only use original full name if 
                # it's larger than the concatenation
                # of first and last names, to prevent
                # wrong order of names in full name.
                fullName = row[0]
                concatenatedFullName = row[1] + ' ' + row[2]
                if not fullName or len(fullName) <= len(concatenatedFullName):
                    fullName = concatenatedFullName

                firstName = row[1]
                if not firstName:
                    firstName = fullName
                cellPhone = row[4]
                if not cellPhone:
                    cellPhone = row[5]
                if not cellPhone:
                    cellPhone = row[26]

                vcf.write(
                        'BEGIN:VCARD' + '\n' +
                        'VERSION:3.0' + '\n' +
                        'N:' + row[2] + ';' + firstName + '\n' +
                        'FN:' + fullName + '\n' +
                        'TEL;TYPE=CELL:' + cellPhone + '\n' +
                        'TEL;TYPE=HOME:' + row[6] + '\n'
                        'TEL;TYPE=WORK:' + row[7] + '\n'
                        'EMAIL:' + row[9] + '\n' +
                        'ADR;TYPE=HOME:;;' + row[10] + '\n' +
                        'NOTE:' + row[11] + '\n' +
                        'END:VCARD' + '\n')

def main(args):
    if len(args) != 2:
        print('Usage:')
        print(args[0] + ' csv_filename')
        return

    filename = args[1]
    encoding = 'utf-8'
    try:
        with open(filename, 'r') as source:
            source.read()
    except UnicodeDecodeError:
        encoding = 'iso-8859-1'
    convert(filename, encoding)

if __name__ == '__main__':
    main(sys.argv)
