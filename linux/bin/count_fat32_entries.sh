#!/usr/bin/env bash

# Count number of FAT32 directory entries used in current directory.

# FAT32 File System Specification:
# https://www.microsoft.com/whdc/system/platform/firmware/fatgen.mspx
# https://www.forensicswiki.org/wiki/FAT

# Basically, there's one directory entry that always holds the short
# (8.3) version of the file name. If the actual name doesn't fit that
# mold, then there will be one to twelve more entries, each of which
# holds 13 bytes of the full name. So a file named
# "veryverylongname.txt" would take three entries. The first would have
# the short name, something like "veryve~1.txt", the second would have
# "veryverylongn", and the third would have "ame.txt". 
# http://web.archive.org/web/20150927164430/http://help.lockergnome.com/windows2/file-folder-limits--ftopict450749.html

set -eu

dir=${1:-.}
[ -d "$dir" ]

entries=0
while read -r i; do
  set +e
  echo "$i" | grep -q '\..\{3\}$'
  extension_check_code=$?
  set -e

  # Short name
  entries=$((entries + 1))
  chars=${#i}
  if [ "$chars" -lt 9 ]; then
    continue
  elif [ "$chars" -lt 13 ] && [ "$extension_check_code" -eq 0 ]; then
    continue
  fi

  # Round up: replace X / Y with (X + Y - 1) / Y
  # https://stackoverflow.com/a/24253318
  entries=$((entries + ( (chars + 13 - 1) / 13 ) ))
done <<< "$(find . -maxdepth 1 -print0 | xargs -0 -I{} basename "{}")"

echo "Total entries: $entries, free entries: $((65534 - entries))"
