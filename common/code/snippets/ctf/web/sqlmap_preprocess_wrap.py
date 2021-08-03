#!/usr/bin/env python3

import hashlib
import re
import urllib

def preprocess(req):
    if req.data:
        data = urllib.parse.parse_qs(req.data)
        if b'email' in data:
            digest = hashlib.md5(data[b'email'][0]).hexdigest()
            req.data = re.sub(b'FIXME', bytes(digest, encoding='latin-1'), req.data)
    return req
