#!/usr/bin/env bash

set -eu

echo -n '' > ./index.md
while read -r i; do
  b=$(basename "$i")
  echo "- [$b]($i)" >> ./index.md
done <<< "$(find . -type f | sort)"
