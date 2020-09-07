#!/usr/bin/env python2

from sys import argv
from omg import *
from omg.mapedit import *
import math
import pprint


def relight(map):
    ed = MapEditor(map)
    levels = {}
    for s in ed.sectors:
        if s.light not in levels:
            levels[s.light] = 0
        levels[s.light] += 1
    pprint.pprint(levels)
    return ed.to_lumps()


def main(args):
    if len(args) < 1:
        print "    Omgifol script: dump light levels\n"
        print "    Usage:"
        print "    light.py input.wad [pattern]\n"
        print "    Dump all maps or those whose name match the given pattern"
        print "    (eg E?M4 or MAP*)."
    else:
        print "Loading %s..." % args[0]
        inwad = WAD()
        inwad.from_file(args[0])
        pattern = "*"
        if len(args) == 2:
            pattern = args[1]
        for name in inwad.maps.find(pattern):
            relight(inwad.maps[name])


if __name__ == "__main__":
    main(argv[1:])
