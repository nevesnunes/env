#!/bin/sh

# Bruteforce text encodings.

# Alternatives:
# - https://www.freedesktop.org/wiki/Software/uchardet/
# - https://pypi.org/project/charset-normalizer/

set -u

needle=$1
target_file=$2

needle_file=$(mktemp)
needle_encoded_file=$(mktemp)
trap 'rm -f -- "$needle_file" "$needle_encoded_file"' EXIT INT QUIT TERM 

printf '%s' "$needle" > "$needle_file"

for charset in \
    koi8-r windows-1251 \
    shift-jis euc-jp iso-2022-jp \
    custom-16be custom-16le \
    utf-8 utf-16be utf-16le \
    latin1; do
  if echo "$charset" | grep -q custom-16be; then
    needle_encoded=$(printf '%s' "$needle" | xxd -p | sed 's/\(..\)/\\x\1./g')
  elif echo "$charset" | grep -q custom-16le; then
    needle_encoded=$(printf '%s' "$needle" | xxd -p | sed 's/\(..\)/.\\x\1/g')
  else
    if ! iconv -f UTF-8 -t "$charset" "$needle_file" -o "$needle_encoded_file"; then
      echo "$charset:[SKIPPED]"
      continue
    fi
    needle_encoded=$(xxd -p "$needle_encoded_file" | sed 's/\(..\)/\\x\1/g')
  fi
  echo "$charset:$needle_encoded"
  env LANG=C grep --color=auto -PHoba "$needle_encoded" "$target_file"
done
