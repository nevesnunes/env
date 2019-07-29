#!/usr/bin/env bash

# [Encoding Set] Canonical name for `java.lang` API:
# https://docs.oracle.com/javase/7/docs/technotes/guides/intl/encoding.doc.html

set -eu

source_file=$(mktemp)
target_file=$(mktemp)
cleanup() {
  rm -f "$source_file" "$target_file"
}
trap cleanup EXIT INT QUIT TERM

while read -r i; do
  echo -n "$i" > "$source_file"
  native2ascii -encoding UTF8 "$source_file" "$target_file"
  cat "$target_file"
done
