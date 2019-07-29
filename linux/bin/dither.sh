#!/usr/bin/env bash

set -eux

format="aresample=resampler=soxr:dither_method=f_weighted:dither_scale=0.5,aformat=s16:44100"

tmp_dir=$(mktemp -d)
[ -d "$tmp_dir" ]
trap 'rmdir "$tmp_dir"' EXIT QUIT INT TERM

while read -r i; do
  if ! file --mime-type "$i" | grep -qi '\(audio\|octet-stream\)'; then
    continue
  fi

  ffmpeg -i "$i" -af "$format" -vn "$tmp_dir/${i%.*}.flac" </dev/null

  rm "$i"
done <<< "$(find . -maxdepth 1 -type f | sed 's/^\.\///')"
mv "$tmp_dir"/*.flac ./

cat > "info.dither.txt" << EOF
Dither command:
ffmpeg -i "\$input_file" -af "$format" -vn "\$output_file"

Versions:
$(ffmpeg -version | head -n1)
$(sox --version | sed 's/^sox:\s*//')
EOF
