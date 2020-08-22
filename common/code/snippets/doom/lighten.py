#!/usr/bin/env python2

from sys import argv
from omg import *
from omg.mapedit import *
import math


def relight(map):
    ed = MapEditor(map)
    for s in ed.sectors:
        if (s.light / 255.0 <= 0.04045):
            s.light = int(s.light / 12.92)
        else:
            s.light = int(255 * (((s.light / 255.0) + 0.055) / 1.055)**2.4)

    return ed.to_lumps()


def main(args):
    if (len(args) < 2):
        print "    Omgifol script: change light levels\n"
        print "    Usage:"
        print "    light.py input.wad output.wad [pattern]\n"
        print "    Relight all maps or those whose name match the given pattern"
        print "    (eg E?M4 or MAP*)."
    else:
        print "Loading %s..." % args[0]
        inwad = WAD()
        outwad = WAD()
        inwad.from_file(args[0])
        pattern = "*"
        if (len(args) == 3):
            pattern = args[2]
        for name in inwad.maps.find(pattern):
            print "Relighting %s" % name
            outwad.maps[name] = relight(inwad.maps[name])
        print "Saving %s..." % args[1]
        outwad.to_file(args[1])


if __name__ == "__main__":
    main(argv[1:])
