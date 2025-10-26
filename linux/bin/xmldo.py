#!/usr/bin/env python2
# encoding: utf-8

# Dependencies:
# python2 -m pip install beautifulsoup4 lxml

import sys

from bs4 import BeautifulSoup

if __name__ == "__main__":
    filename = sys.argv[1]
    node = sys.argv[2]
    append = ''
    attr = ''
    dump = ''
    find = ''
    test_child = ''
    test_child_value = ''
    test_parent = ''
    args = iter(xrange(3,len(sys.argv)))
    for i in args:
        arg = sys.argv[i]
        if arg == '--append':
            append = sys.argv[i+1]
            next(args)
        elif arg == '--attr':
            attr = sys.argv[i+1]
            next(args)
        elif arg == '--dump':
            dump = sys.argv[i+1]
            next(args)
        elif arg == '--find':
            find = sys.argv[i+1]
            next(args)
        elif arg == '--test_child':
            test_child = sys.argv[i+1]
            next(args)
        elif arg == '--test_child_value':
            test_child_value = sys.argv[i+1]
            next(args)
        elif arg == '--test_parent':
            test_parent = sys.argv[i+1]
            next(args)

    with open(filename) as data:
        soup = BeautifulSoup(data.read(), 'xml')
        nodes = soup.findAll(node)
        if find:
            if not attr:
                for tag in nodes:
                    print str(tag)
            else:
                results = [tag[attr] for tag in nodes]
                for result in results:
                    print result
        elif append:
            for tag in nodes:
                if test_parent and not tag.parents.next().name == test_parent:
                    continue
                if test_child:
                    children = tag.findChildren()
                    found_child = ''
                    for child in children:
                        if child.name == test_child:
                            found_child = child
                            break
                    if found_child:
                        if test_child_value and not found_child.contents[0] == test_child_value:
                            continue
                    else:
                        continue
                # Skip xml header
                soup_append = BeautifulSoup(append, 'xml')
                tag.append(soup_append.find(''))
        if dump:
            with open(dump, "wb") as file:
                file.write(str(soup))
