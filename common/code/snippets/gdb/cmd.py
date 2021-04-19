#!/usr/bin/env python3

# Source with `gdb -x $0.py`

import gdb


class Cmd(gdb.Command):
    def __init__(self):
        super(Cmd, self).__init__("foo", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        print("bar")


Cmd()
