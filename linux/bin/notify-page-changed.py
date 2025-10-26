#!/usr/bin/env python3

import argparse
import re
import requests
import subprocess
import sys
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument("url", type=str)
parser.add_argument("--interval", type=int, default=60 * 5)
args = parser.parse_args()

initial_contents = None
with tempfile.NamedTemporaryFile(delete=False) as tmp:
    print(f"Checking {args.url}...")
    while True:
        try:
            respond = requests.get(args.url)
            if respond.status_code == 200:
                clean_text = re.sub('[0-9]+[:/-][0-9]+[:/-][0-9]+', '___', respond.text)
                if not initial_contents:
                    tmp.write(bytes(clean_text, encoding='utf-8'))
                    print(clean_text)

                    initial_contents = clean_text
                elif clean_text != initial_contents:
                    tmp.write(bytes(clean_text, encoding='utf-8'))
                    print(clean_text)

                    subprocess.run(["notify-send", "Changed!", tmp.name])
                    print(["notify-send", "Changed!", tmp.name])

                    break
            else:
                print(respond.status_code)
                print(respond.text)
        except Exception as e:
            print(e)

        time.sleep(args.interval)
