#!/usr/bin/env bash

# [Encoding Set] Canonical name for `java.lang` API:
# https://docs.oracle.com/javase/7/docs/technotes/guides/intl/encoding.doc.html

set -eu

# TODO: convert encoding
#f="$i" && iconv -f iso-8859-1 -t utf-8 "$f" > "$f.tmp" && mv "$f.tmp" "$f"
while read -r i; do
  if file -ib "$i" | grep -qi 'utf-\?8'; then
    native2ascii -encoding UTF8 "$i" "$i.tmp" && mv "$i.tmp" "$i"
  else
    native2ascii "$i" "$i.tmp" && mv "$i.tmp" "$i"
  fi
done <<< "$(find . -iname '*.properties*')"
