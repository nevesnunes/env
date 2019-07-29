#!/usr/bin/env bash

set -xe

openssl genrsa -out mitmproxy.key 2048
openssl req -new -x509 -key mitmproxy.key -out mitmproxy.crt -days 3650 -subj /CN=MitmProxy
cat mitmproxy.key mitmproxy.crt > mitmproxy.pem
start "" mitmproxy.crt
