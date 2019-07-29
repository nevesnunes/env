#!/usr/bin/env bash

set -eu

url="$1"

domains=$(echo "$url" | sed 's/https\?:\/\/\([^\/]*\).*/\1/g')
wget \
    --no-use-server-timestamps \
    --adjust-extension \
    --page-requisites \
    --no-use-server-timestamps \
    --span-hosts \
    --convert-links \
    --backup-converted \
    --limit-rate=500k --random-wait --wait=0.5 \
    --recursive \
    --domains "$domains" \
    -e robots=off \
    "$url"
