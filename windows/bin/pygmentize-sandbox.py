#!/usr/bin/env python2
# -*- encoding: utf-8 -*-

from __future__ import unicode_literals

import sys

from pygments import highlight
from pygments.lexers import SqlLexer
from pygments.formatters import TerminalFormatter

#in_ = sys.stdin.read()
#print highlight(in_, SqlLexer(), TerminalFormatter())

from pygments.lexers import get_all_lexers
i = get_all_lexers()
while True:
    try:
        o = i.next()
        extensions = ','.join(o[2])
        if not extensions:
            continue
        print("fileviewer {0} pygmentize -l {1}".format(extensions, o[1][0]))
    except StopIteration:
        break
    except Exception as e:
        print(e)
