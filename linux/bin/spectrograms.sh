#!/bin/sh

set -eu

mkdir -p ./Spectrograms

files=$(find . -maxdepth 1 -type f | sed 's/^\.\///')
set -f; IFS='
'
for file in $files; do
  set +f; unset IFS

  if ! file --mime-type "$file" \
    | awk -F':' '{print $NF}' \
    | grep -qi '\(audio\|octet-stream\)'; then
    continue
  fi

  target_filename=./Spectrograms/"${file%.*}.png"
  test -f "$target_filename" \
    || sox "$file" -n spectrogram -o "$target_filename"
done
set +f; unset IFS

set -- ./Spectrograms/*
test -f "$1" \
  && xdg-open "$1"
