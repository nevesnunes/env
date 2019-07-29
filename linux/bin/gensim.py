#!/usr/bin/env python2

import sys
from gensim.summarization import keywords

if __name__ == "__main__":
    filename = sys.argv[1]
    text = open(filename, 'r')
    print keywords(text, ratio=0.01)
    print '\n'
    print keywords(text, word_count=5)
