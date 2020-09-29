#!/usr/bin/env python3

from ipdb import launch_ipdb_on_exception
import base64
import binascii
import json
import os
import sys

with open(sys.argv[1], "r") as f:
    contents = f.read()

out_dir = './out'
if not os.path.exists(out_dir):
    os.makedirs(out_dir)

with launch_ipdb_on_exception():
    packets = json.loads(contents)
    for i, packet in enumerate(packets):
        if "tcp" not in packet["_source"]["layers"]:
            continue

        data = packet['_source']['layers']['tcp']['tcp.payload'].replace(':', '')
        hex_bytes_clean = ''.join(data.split())
        raw_bytes = binascii.a2b_hex(hex_bytes_clean)
        #parsed_data = json.loads(raw_bytes)['data']

        #is_decoded = False
        #while not is_decoded:
        #    try:
        #        decoded_data = base64.b64decode(parsed_data)
        #        is_decoded = True
        #    except binascii.Error:
        #        parsed_data += '0'

        #raw_bytes = decoded_data

        with open("{}/{:08d}".format(out_dir, i), 'wb') as f:
            f.write(raw_bytes)

