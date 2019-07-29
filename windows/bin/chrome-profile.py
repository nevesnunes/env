#!/usr/bin/env python2
# -*- encoding: utf-8 -*-

from __future__ import unicode_literals

import json
import os
import pylev
import re
import sys

def find(key, dictionary):
    for k, v in dictionary.iteritems():
        if k == key:
            yield v
        elif isinstance(v, dict):
            for result in find(key, v):
                yield result
        elif isinstance(v, list):
            for d in v:
                if isinstance(d, dict):
                    for result in find(key, d):
                        yield result

try:
    import colorama
    colorama.init()
    def highlight_name(text):
        return colorama.Fore.RED + \
                colorama.Style.BRIGHT + \
                text + \
                colorama.Style.RESET_ALL
    def highlight_snippet(text):
        return colorama.Fore.YELLOW + \
                colorama.Style.BRIGHT + \
                text + \
                colorama.Style.RESET_ALL
except ImportError:
    def highlight_name(text):
        return text
    def highlight_snippet(text):
        return text

filename = ''
printSnippets = False
args = sys.argv[1:]
while len(args):
    value = args[0]
    if value == "-s" or value == "--snippets":
        printSnippets = True
    else:
        filename = value
    args = args[1:]

# TODO: Filter with json-schema
with open(filename, "rb") as f:
    paths = {}
    cwd = os.getcwd()
    for root, dirnames, filenames in os.walk(cwd):
        for filename in filenames:
            realpath = os.path.join(root, filename)
            parts = realpath.decode("utf-8").split('/')
            name = parts[len(parts) - 1]
            if name not in paths:
                paths[name] = [];
            paths[name].append(realpath)

    needle = 'callFrame'
    o = json.load(f)
    if isinstance(o, list):
        j = {}
        j["root"] = o
        o = j
    matches = list(find(needle, o))
    for match in matches:
        if not "url" in match or \
                not "functionName" in match or \
                re.match(r"^(chrome-extension:|extensions:|native\ )", match["url"]) or \
                re.match(r"^.*(angular|bootstrap|jquery)[^/]*.js", match["url"]) or \
                re.match(r"^.*[-\.]min.js", match["url"]):
                    continue

        functionName = highlight_name(match["functionName"])
        url = match["url"]
        lineNumber = match["lineNumber"]
        print("{0}:{1}:{2}".format(url, lineNumber, functionName))

        #
        # Retrieve snippet
        #

        if not printSnippets:
            continue

        candidateParts = url.split('/')
        candidateName = candidateParts[len(candidateParts) - 1]
        if candidateName not in paths:
            continue

        candidatePaths = paths[candidateName]
        bestDistance = 9999
        bestPath = ''
        for candidatePath in candidatePaths:
            distance = pylev.damerau_levenshtein(candidatePath, url)
            if (distance < bestDistance):
                bestDistance = distance
                bestPath = candidatePath
        if not bestPath:
            continue 

        with open(bestPath, "rb") as f2:
            lines = f2.readlines()
            snippet = lines[lineNumber:lineNumber+5]
            print(highlight_snippet(''.join(snippet)))
