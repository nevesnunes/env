#!/usr/bin/env bash

set -eux

mkdir -p md
while read -r i; do
  target_name=$(basename "$i")
  pandoc -s "$i" -o md/"${target_name%.*}".md
done <<< "$(find . -iname '*.docx')"
