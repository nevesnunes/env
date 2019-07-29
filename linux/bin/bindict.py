#!/usr/bin/env python2
# encoding: utf-8

# Dependencies:
# python2 -m pip install beautifulsoup4 lxml

import re
import sys

from bs4 import BeautifulSoup
import nltk
from nltk.corpus import words
from nltk.corpus import wordnet

from nltk.stem.wordnet import WordNetLemmatizer
Lemmatizer = WordNetLemmatizer()

allWords = set(word.lower() for word in wordnet.words()).union(
    set(word.lower() for word in words.words()))

if __name__ == "__main__":
    filename = sys.argv[1]
    needle = sys.argv[2]
    with open(filename) as data:
        soup = BeautifulSoup(data.read(), 'lxml')
        nodes = soup.find_all(class_=needle)
        binWords = set()
        for node in nodes:
            tokens = nltk.word_tokenize(node.text)
            for token in tokens:
                if not re.match(".*[A-Za-z]+.*", token):
                    continue
                processedToken = Lemmatizer.lemmatize(token.lower())
                if not processedToken in allWords:
                    binWords.add(processedToken)
        for word in binWords:
            print(word)
