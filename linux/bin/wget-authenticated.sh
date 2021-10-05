#!/bin/sh

# `--user-agent`: Unused, since credentials stored in
# cookies may depend on the user-agent of the browser
# that generated them
#
# `--span-hosts`: Used if assets stored in different subdomains

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
  --limit-rate=500k --random-wait --wait=0.5 \
  --load-cookies "$cookies" \
  --max-redirect=20 \
  --no-parent \
  --no-use-server-timestamps \
  --page-requisites \
  --span-hosts \
  --trust-server-names \
  "$url"
