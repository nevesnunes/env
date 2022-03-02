#!/bin/sh

set -eu

mkdir -p ./Spectrograms

if [ $# -gt 0 ]; then
  files=$*
else
  files=$(find . -maxdepth 1 -type f | sed 's/^\.\///')
fi
set -f; IFS='
'
for file in $files; do
  set +f; unset IFS

  if ! file --mime-type "$file" \
    | awk -F':' '{print $NF}' \
    | grep -qi '\(audio\|octet-stream\|mp4\)'; then
    continue
  fi

  # Ignore false positives from `octet-stream` files
  target_filename=./Spectrograms/"${file%.*}.png"
  test -f "$target_filename" \
    || sox "$file" -n spectrogram -o "$target_filename" \
    || true
done
set +f; unset IFS

set -- ./Spectrograms/*
test -f "$1" \
  && xdg-open "$1"
