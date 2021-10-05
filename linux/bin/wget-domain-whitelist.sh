#!/bin/sh

# Usage:
# - export all cookies to a Netscape HTTP Cookie File
# - e.g. tumblr post
#     ./$0 'https://foo.tumblr.com/post/123#notes' 'foo.tumblr.com/post,assets.tumblr.com,media.tumblr.com,static.tumblr.com,bootstrapcdn.com,googleapis.com' ~/Downloads/cookies.txt

set -eux

url=$1
domains=${2:-""}
[ -n "$domains" ] || domains=$(echo "$url" | sed 's/https\?:\/\/\([^\/]*\).*/\1/g')
cookies_file=${3:-}
if [ -n "$cookies_file" ]; then
  cookies=$(realpath "$cookies_file")
  [ -f "$cookies" ]
  sed -i 's/#HttpOnly_//g' "$cookies"
else
  cookies=/dev/null
fi
# `--follow-tags`: Defined in: html-url.c:known_tags
wget \
  --adjust-extension \
  --backup-converted \
  --convert-links \
  --domains "$domains" \
  -e robots=off \
  --header='Accept-Language: en,en-US;q=0.5' \
  --level=20 \
  --limit-rate=500k --random-wait --wait=0.2 \
  --load-cookies "$cookies" \
  --page-requisites \
  --recursive \
  --span-hosts \
  --timestamping \
  --trust-server-names \
  --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36" \
  "$url"
