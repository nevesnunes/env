#!/bin/sh

# Usage (comparing pdfs with missing page):
# qpdf foo.pdf --pages . 2-10 -- bar.pdf 
# convert foo.pdf foo/'%d.png'
# convert bar.pdf bar/'%d.png'
# ./diff-images foo/ 0 bar/ 1

set -eux

source_dir=$1
source_i=$2
target_dir=$3
target_i=$4
output_dir=${5:-$(mktemp -d)}

source_max=$(find "$source_dir" -maxdepth 1 -type f -printf '.' \
  | wc -c)
target_max=$(find "$target_dir" -maxdepth 1 -type f -printf '.' \
  | wc -c)
if [ "$source_max" -gt "$target_max" ]; then
  length=$(($target_max + 1))
else
  length=$(($source_max + 1))
fi
while [ $((source_i)) -lt "$length" ]; do
  # References: 
  # - https://stackoverflow.com/questions/27974945/can-we-programmatically-compare-different-images-of-same-resolutions
  # - http://www.imagemagick.org/Usage/compare/#statistics
  compare \
    "$source_dir/$source_i".* \
    "$target_dir/$target_i".* \
    -metric RMSE \
    "$output_dir/${source_i}_${target_i}.png"
  source_i=$((source_i + 1))
  target_i=$((target_i + 1))
done
