#!/bin/sh

set -eu

mkdir -p ./Spectrograms

if [ $# -eq 0 ]; then
  set -- "$(find . -maxdepth 1 -type f | sed 's/^\.\///')"
fi
set -f; IFS='
'
for file in $@; do
  set +f; unset IFS

  if ! file --mime-type "$file" \
    | awk -F':' '{print $NF}' \
    | grep -qi '\(audio\|octet-stream\|mp4\)'; then
    continue
  fi

  # Ignore false positives from `octet-stream` files
  target_filename=./Spectrograms/$(basename "${file%.*}.png")
  test -f "$target_filename" \
    || sox "$file" -n spectrogram -o "$target_filename" \
    || true
done
set +f; unset IFS

set -- ./Spectrograms/*
test -f "$1" \
  && xdg-open "$1"
