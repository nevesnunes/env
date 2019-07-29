#!/usr/bin/env bash

set -eu

file=$1
[ -f "$file" ] || exit 1

name=$(grep -ao 'name[0-9]*:[^:]*:' "$file" | \
    sed 's/.*name[0-9]*:\([^:]*\):.*/\1/g')
[ -n "$name" ] && mv "$file" "$name.torrent"
