#!/bin/sh

# TODO: Generate user agent from browser that generated cookies file
# - make request with webdriver / headless instance, take user agent from headers
# - static analysis:
# browser_version=$(rpm -q firefox | sed 's/firefox-\([0-9]*\.[0-9]*\).*/\1/')
# strings --print-file-name /usr/lib64/firefox/* | grep 'Mozilla/5.0'
# =>
# /usr/lib64/firefox/libxul.so: Mozilla/5.0 (%s; rv:%d.0) Gecko/%s Firefox/%d.0

set -eux

url=${1%/}
cookies_file=${2:-}
if [ -n "$cookies_file" ]; then
  cookies=$(realpath "$cookies_file")
  [ -f "$cookies" ]
  sed -i 's/#HttpOnly_//g' "$cookies"
else
  cookies=/dev/null
fi
wget \
  --adjust-extension \
  --convert-links \
  -e robots=off \
  --header='Accept-Language: en,en-US;q=0.5' \
  --limit-rate=500k --random-wait --wait=1.5 \
  --load-cookies "$cookies" \
  --max-redirect=20 \
  --no-parent \
  --page-requisites \
  --server-response \
  --timestamping \
  --trust-server-names \
  --user-agent="Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" \
  "$url"
