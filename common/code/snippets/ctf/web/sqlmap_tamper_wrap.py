#!/usr/bin/env python3

from lib.core.enums import PRIORITY
import urllib.parse

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    retVal = payload

    if payload:
        ws = urllib.parse.quote(" ")
        retVal = f"'{ws}or{ws}({payload})--'"

    return retVal
