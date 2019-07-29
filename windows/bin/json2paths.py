#!/usr/bin/env python3

import json
import sys

def path(obj, pre=""):
    """
    Recursivly goes through the dictionnary obj and replaces keys with the convert function.
    """
    if isinstance(obj, dict):
        if 'name' in obj:
            name = obj['name']
            if 'contents' in obj:
                pre += "/" + name
                path(obj['contents'], pre)
            else:
                print(pre)
    elif isinstance(obj, list):
        for v in obj:
            path(v, pre)
    return pre

def change_keys(obj, convert):
    """
    Recursivly goes through the dictionnary obj and replaces keys with the convert function.
    """
    if isinstance(obj, dict):
        new = {}
        if 'name' in obj:
            name = obj['name']
            if 'contents' in obj:
                new[name] = change_keys(obj['contents'], convert)
            else:
                new[name] = 1
    elif isinstance(obj, list):
        new = []
        for v in obj:
            new.append(change_keys(v, convert))
    else:
        return obj
    return new

def dict_generator(indict, pre=None):
    pre = pre[:] if pre else []
    if isinstance(indict, dict):
        for key, value in indict.items():
            if isinstance(value, dict):
                for d in dict_generator(value, [key] + pre):
                    yield d
            elif isinstance(value, list) or isinstance(value, tuple):
                for v in value:
                    for d in dict_generator(v, [key] + pre):
                        yield d
            else:
                yield pre + [key, value]
    else:
        yield indict

with open(sys.argv[1], "rb") as f:
    o = json.load(f)
    path(o)
    #o = change_keys(o, None)
    #print(json.dump(o, sys.stdout))
    #for a in dict_generator(o):
    #    print(a)
