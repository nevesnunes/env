#!/bin/sh

set -eu

binary_file=$(realpath "$*")
test -f "$binary_file"

plaintext_root=$HOME/code/plaintext_root
mkdir -p "$plaintext_root"

binary_file_dir=$(dirname "$binary_file")
target_dir=$plaintext_root/${binary_file_dir#$HOME/}
mkdir -p "$target_dir"

plaintext_file=$target_dir/$(basename "$binary_file")
plaintext_file=${plaintext_file%.*}.txt
if ! [ -f "$plaintext_file" ]; then
  extension=${binary_file##*.}
  case "$extension" in
  pdf)
    plaintext_file_basename=$(basename "$binary_file")
    plaintext_file_basename=${plaintext_file_basename%.*}.txt
    pdftotext -enc UTF-8 "$binary_file" \
      && mv "$binary_file_dir/$plaintext_file_basename" "$plaintext_file" >/dev/null 2>&1
    ;;
  epub|mobi)
    ebook-convert "$binary_file" "$plaintext_file" >/dev/null 2>&1
    ;;
  *)
    # Can't convert file, no plaintext available
    exit
  esac
fi

echo "$plaintext_file"
