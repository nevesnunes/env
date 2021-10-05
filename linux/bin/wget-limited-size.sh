#!/usr/bin/env bash

set -u

url=${1%/}/
size=$2
while read -r i; do
  curl --max-filesize "$size" "$i" -o "$(basename "$i")"
  sleep 0.5
done <<< "$(wget-path-whitelist.sh "$url" 2>&1 | \
  grep -oE "$url.*" | \
  grep -v "$url\\(?.*\\)\\?$")"
