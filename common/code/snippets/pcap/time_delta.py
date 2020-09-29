#!/usr/bin/env python3

from ipdb import launch_ipdb_on_exception
import collections
import json
import os
import sys

with open(sys.argv[1], "r") as f:
    contents = f.read()

streams = collections.OrderedDict()

with launch_ipdb_on_exception():
    packets = json.loads(contents)
    for i, packet in enumerate(packets):
        if "tcp" not in packet["_source"]["layers"]:
            continue

        stream = packet['_source']['layers']['tcp']['tcp.stream']
        if stream not in streams:
            streams[stream] = 0;

        data = packet['_source']['layers']['tcp']['Timestamps']['tcp.time_delta'].replace(':', '')
        data = ''.join(data.split())
        streams[stream] += float(data)

    for key, value in streams.items():
        print(value)
