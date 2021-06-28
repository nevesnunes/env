#!/usr/bin/env python3

from socket import *
import sys

interface = "ens33" # Change
data = sys.stdin.buffer.read()
s = socket(AF_PACKET, SOCK_RAW)
s.bind((interface, 0))
s.send(data)
