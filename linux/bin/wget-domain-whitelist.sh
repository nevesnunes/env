#!/usr/bin/env bash

# Usage:
# - export all cookies to a Netscape HTTP Cookie File
# - e.g. tumblr post
#     ./$0 'https://foo.tumblr.com/post/123#notes' 'foo.tumblr.com/post,media.tumblr.com' ~/Downloads/cookies.txt

set -eu

url=$1
domains=${2:-""}
[ -n "$domains" ] || domains=$(echo "$url" | sed 's/https\?:\/\/\([^\/]*\).*/\1/g')
# `--follow-tags`: Defined in: html-url.c:known_tags
wget \
    --adjust-extension \
    --backup-converted \
    --convert-links \
    --domains "$domains" \
    -e robots=off \
    --limit-rate=500k --random-wait --wait=0.2 \
    --no-use-server-timestamps \
    --page-requisites \
    --recursive \
    --level=20 \
    --span-hosts \
    --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36" \
    "$url"
