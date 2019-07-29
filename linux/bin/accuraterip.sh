#!/usr/bin/env bash

set -eu

cue_file=$1
if [ ! -f "$cue_file" ]; then
  echo "Error: $cue_file is not a file"
  exit 1
fi
track_count=$(grep -ci 'track\s*[0-9]*\s*audio' "$cue_file")
if [ -z "$track_count" ]; then
  echo "Error: Track count = 0"
  exit 1
fi

accuraterip_checksum_bin=$HOME/opt/accuraterip-checksum/accuraterip-checksum
track_num=1
while read -r i; do {
  if ! file --mime-type "$i" | grep -qi '\(audio\|octet-stream\)'; then
    continue
  fi

  checksum=$("$accuraterip_checksum_bin" "$i" "$track_num" "$track_count")
  echo "    Track Name : $i"
  echo "AccurateRip v2 : $checksum"
  echo ""

  track_num=$(($track_num + 1))
} || true
done <<< "$(find . -maxdepth 1 -type f | sed 's/^\.\///' | sort -V)"
