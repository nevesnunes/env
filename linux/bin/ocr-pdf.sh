#!/bin/sh

set -eux

pdf_file=$1
test -f "$pdf_file"
out_file=$(dirname "$(realpath "$pdf_file")")/$(basename "${pdf_file%.*}").ocr
tmp_dir=$(mktemp -d)

cleanup() {
  err=$?
  rm -rf "$tmp_dir"
  trap '' EXIT
  exit $err
}
trap cleanup EXIT INT QUIT TERM

convert -monochrome -density 300 "$pdf_file" "$tmp_dir"/out-%3d.tif
tesseract "$tmp_dir"/out-%3d.tif "$out_file" pdf
