#!/usr/bin/env python3

from threading import *

from terminal import *
import listener

cmd = ''

if __name__ == '__main__':
    term = Terminal()
    t = Thread(target = term.cmdloop,)
    t.start()

    listener.run()
