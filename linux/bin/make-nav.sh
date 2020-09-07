#!/usr/bin/env bash

set -eu

while read -r i; do
  b=$(basename "$i")
  echo "- ${b%.*}: '$i'"
done <<< "$(find . -type f | sort)"
