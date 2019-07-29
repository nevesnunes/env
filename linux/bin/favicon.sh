#!/bin/sh

set -eux

img_file=$1
[ -f "$img_file" ]

for i in 16 32 48; do
  # density value: https://stackoverflow.com/questions/7442665/convert-svg-file-to-multiple-different-size-png-files/41765568#41765568
  convert -density 1536 -resize "${i}x${i}"! "$img_file" "${i}".png
done
cleanup() {
  err=$?
  rm -f 16.png 32.png 48.png
  trap '' EXIT
  exit $err
}
trap cleanup EXIT INT QUIT TERM

ect_bin="$HOME/code/src/graf/Efficient-Compression-Tool/build/ect"
if [ -x "$ect_bin" ]; then
  for i in *.png; do
    "$ect_bin" \
      -9 \
      -strip \
      --strict \
      --allfilters \
      --mt-deflate=2 \
      --pal_sort=120 \
      "$i"
  done
fi

convert 16.png 32.png 48.png favicon.ico
