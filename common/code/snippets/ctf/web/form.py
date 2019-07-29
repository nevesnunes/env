#!/usr/bin/env python

import urllib
from requests.auth import HTTPBasicAuth
import requests

from bs4 import BeautifulSoup

# Build the request
headers = {
    'Host': 'EXAMPLE.com',
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:50.0) Gecko/20100101 Firefox/50.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Referer': 'http://EXAMPLE.com/index.php',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1'
}
data = {
    'PARAM1': 'VALUE1',
    'PARAM2': 'VALUE2'
}
cookies = {
    'PARAM1': 'VALUE1',
    'PARAM2': 'VALUE2'
}

# Send the request
url = 'http://EXAMPLE.com/index.php'
result = requests.post(url, data=data, headers=headers, cookies=cookies)

# Print returned page
page = BeautifulSoup(result.text, 'lxml')
print page

# Print a specific DOM element
page_element = page.find("div", {"id": "EXAMPLE"})
print page_element

# Check for a pattern in a specific DOM element
if page_element:
    pattern = ".*EXAMPLE.*"
    text = ''.join(map(str, page_element.contents))
    match = re.search(pattern, text, flags=re.IGNORECASE)
    if match:
        print page_element
