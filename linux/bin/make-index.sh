#!/usr/bin/env bash

set -eu

echo -n '' > ./index.md
while read -r i; do
  [ -d "$i" ] && continue
  echo "# $i" >> ./index.md
done <<< "$(find . | sort)"
