#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import time
import socket
import sys

HOST = sys.argv[1]
PORT = int(sys.argv[2])

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tries = 2
while tries:
    try:
        s.connect((HOST, PORT))
        break
    except:
        tries -= 1
        time.sleep(1)
if not tries:
    sys.exit(1)
if len(sys.argv) > 3 and sys.argv[3] == "-z":
    sys.exit(0)

input_str = sys.stdin.read()
input_str = input_str.lstrip().rstrip()
s.send(input_str.encode("Utf8"))
print(s.recv(1024).decode("Utf8"))
