#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import re
import os
import select
import socket
import sys

indexes = {}

def parse_md(filename):
    with open(filename) as data:
        description=''
        action=''
        for line in data.readlines():
            line = line.rstrip()
            if not line:
                continue
            if re.match("^#.*", line):
                if action:
                    indexes[description.rstrip()] = action.rstrip()
                    description = ''
                    action = ''
                line = re.sub(r'^#*\s*', '', line)
                description+=line + ' '
            else:
                action+=line + '\n'

root_name = os.path.expanduser("~") + "/kb"
for root, dirnames, filenames in os.walk(root_name):
    for filename in filenames:
        if re.match(r".*\.(md|mkd|markdown)$", filename):
            parse_md(os.path.join(root, filename))

HOST = '127.0.0.1'
PORT = 5000

mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
mySocket.bind((HOST,PORT))
while 1:
    mySocket.listen(2)
    connection, address = mySocket.accept()
    already_waited = False
    while 1:
        try:
            ready_to_read, ready_to_write, in_error = \
                select.select([connection,], [connection,], [], 5)
        except select.error:
            # 0 = done receiving, 1 = done sending, 2 = both
            connection.shutdown(2)
            connection.close()
            break
        # Client disconnected
        if len(ready_to_read) > 0 or len(in_error) > 0:
            if already_waited:
                already_waited = False
                break
            else:
                already_waited = True

        msgClient = connection.recv(1024).decode("Utf8")
        candidate = msgClient.lstrip().rstrip()
        if candidate in indexes:
            msgServer = indexes[candidate]
            connection.send(msgServer.encode("Utf8"))
        elif candidate == 'l':
            msgServer = '\n'.join(indexes.keys())
            connection.send(msgServer.encode("Utf8"))
        elif candidate == 'q':
            connection.close()
            sys.exit(0)

    connection.close()
