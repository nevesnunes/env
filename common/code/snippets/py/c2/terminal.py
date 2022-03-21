#!/usr/bin/env python3

from cmd import Cmd

import host

class Terminal(Cmd):
    prompt = '> '
    def default(self, args):
        host.cmd = args
