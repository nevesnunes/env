#!/bin/sh

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
  --limit-rate=500k --random-wait --wait=0.2 \
  --load-cookies "$cookies" \
  --max-redirect=20 \
  --no-parent \
  --no-use-server-timestamps \
  --page-requisites \
  --recursive \
  --trust-server-names \
  --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0" \
  "$url"
