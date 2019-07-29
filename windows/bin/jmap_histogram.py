#!/usr/bin/env python2
# -*- encoding: utf-8 -*-

import sys
import operator

# The histogram file path should be given in argument
# The file should have two columns, key and value 
# Each line in the histogram file should contain the key
# then a space and then the value
# The following code would sum the values against the same 
# key and print the result in descending order

f = open(sys.argv[1]) # Open the histogram file 

# Create histogram map
hist = {}
for line in f:
    line = line.strip()
    if line == "":
        continue
    fields = line.split()
    mtype = fields[0].strip()
    mval = fields[1].strip()

    if mtype in hist:
        hist[mtype] = hist[mtype] + int(mval)
    else:
        hist[mtype] = int(mval)

# Sort in descending order
sorted_hist = reversed(sorted(hist.items(), key=operator.itemgetter(1)))

# print
for i in sorted_hist:
    print i[1], "\t", i[0]
