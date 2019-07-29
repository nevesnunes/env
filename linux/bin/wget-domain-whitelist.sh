#!/usr/bin/env bash

set -eu

url=$1
domains=${2:-""}
[ -n "$domains" ] || domains=$(echo "$url" | sed 's/https\?:\/\/\([^\/]*\).*/\1/g')
wget \
    --adjust-extension \
    --backup-converted \
    --convert-links \
    --domains "$domains" \
    -e robots=off \
    --limit-rate=500k --random-wait --wait=0.5 \
    --no-use-server-timestamps \
    --page-requisites \
    --recursive \
    --span-hosts \
    "$url"
