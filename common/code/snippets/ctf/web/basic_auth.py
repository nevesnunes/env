#!/usr/bin/python
import requests  
from requests.auth import HTTPBasicAuth

url = 'http://127.0.0.1:81/authed/'  
r = requests.get(url, auth=HTTPBasicAuth('username', 'password'))  
print r.text
