#!/usr/bin/env python3

"""
Block URLs matching a regex, by just returning an HTTP 404 code. As addons can be called with an argument,
the file containing the URLs is hardcoded, but could be extracted from an environment variable for example.

Unfortunately in Python, contrary to Rust, you can't define a regex set and try to match any regex for a string.

References:
- https://dev.to/dandyvica/use-mitmproxy-as-a-personal-firewall-4m6h
- https://docs.mitmproxy.org/stable/addons-examples/
"""

import re
from mitmproxy import http
from mitmproxy import ctx


class BlockResource:
    def __init__(self):
        # define a new list for holding all compiled regexes. Compilation is done once when the addon
        # is loaded
        self.urls = []

        # read the configuration file having all string regexes
        for re_url in open("urls.txt"):
            self.urls.append(re.compile(re_url.strip()))

        # log how many URLS we have read
        ctx.log.info(f"{len(self.urls)} urls read")

    def response(self, flow):
        # test if the request URL is matching any of the regexes
        if any(re.search(url, flow.request.url) for url in self.urls):
            ctx.log.info(f"found match for {flow.request.url}")
            flow.response = http.HTTPResponse.make(404)


addons = [BlockResource()]
