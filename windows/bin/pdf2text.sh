#!/usr/bin/env bash

set -eux

mkdir -p md
save_dir=$(realpath ./md)
while read -r i; do
  target_file=$(realpath "$i")
  target_name=$(basename "$i")
  target_dir=$(dirname "$target_file")

  # Avoid misencodings with explicit output filename
  target_output_file="$target_dir/${target_name%.*}.txt"
  pdftotext -enc UTF-8 "$target_file" - > "$target_output_file"

  mv "$target_output_file" "$save_dir"
done <<< "$(find . -iname '*.pdf')"
