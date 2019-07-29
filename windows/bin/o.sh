#!/usr/bin/env bash

line="$*"
target="$line"
echo "$target"
if echo "$line" | grep -qi ".*|.*|[ ]*[SC0-9]*"; then
  part=$(echo "$line" | sed "s/.*|.*|[\\ ]*\([SC0-9]*\).*/\1/g")
  target="https://github.com/koalaman/shellcheck/wiki/$part"
fi

start "$target"
