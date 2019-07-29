#!/usr/bin/env bash

set -eux

while read -r f; do
  iconv -f iso-8859-1 -t utf-8 "$f" > "$f.tmp" &&\
    mv "$f.tmp" "$f"
done <<< "$(find . -type f -print0 |\
  xargs -0 file |\
  grep 'ISO-8859 text' |\
  cut -d':' -f1)"
