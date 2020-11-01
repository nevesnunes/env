#!/usr/bin/env python3

import collections
import os

def countletters(myfile):
    """ Returns a dictionary containing a occurence frequency of each found character"""
    d = collections.defaultdict(int)
    myfile = open(myfile)
    for line in myfile:
        line = line.rstrip('\n')
        for c in line:
            d[c] += 1
    return d

def get_letters_count(myfile):
    """ Gets amount of characters in myfile """
    with open(myfile) as f:
        c = f.read()
        return len(c)

filename = '/tmp/d3.v4.min.js'
freqs = countletters(filename)
file_size = get_letters_count(filename)

percent_freqs = {}
for k,v in freqs.iteritems():
    # Save ASCII code of letter and its occurence frequency
    percent_freqs[ord(k)] = "{0:.8f}".format(v/float(file_size))

# For all other unoccured letters, store occurence = 0
for i in xrange(0, 256):
    if not i in percent_freqs:
        percent_freqs[i] = "{0:.8f}".format(0)
