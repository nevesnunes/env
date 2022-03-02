#!/usr/bin/env bash

# Reduces both bit rate and sample rate.

# Alternative:
# ```
# sox input.flac -G -b 16 output.flac rate -v -L 44100 dither
# ```
#
# References:
# - https://captainrookie.com/how-to-downsample-flac/
# - https://web.archive.org/web/20181203051643/https://people.xiph.org/~xiphmont/demo/neil-young.html
# - https://src.infinitewave.ca/
#     - http://sox.sourceforge.net/SoX/NoiseShaping

set -eux

aresample="aresample=resampler=soxr:dither_method=f_weighted:dither_scale=0.5"

force=
while [ $# -gt 0 ]; do
  case $1 in
  --force | -f) force=1 ;;
  esac
  shift
done

tmp_dir=$(mktemp -d)
[ -d "$tmp_dir" ]
trap 'rmdir "$tmp_dir"' EXIT QUIT INT TERM

while read -r i; do
  if ! file --mime-type "$i" | grep -qi '\(audio\|octet-stream\)'; then
    continue
  fi

  # Downsample to common multiple:
  # - 88.2KHz or 176.4KHz to 44.1KHz
  # - 96KHz or 192KHz to 48KHz
  sample_rate=$(ffprobe -show_streams -select_streams a:0 "$i" 2> /dev/null \
    | grep sample_rate= \
    | grep -o '[0-9]\+')
  if ((sample_rate <= 48000)) && [ -z "$force" ]; then
    echo "Already in target sample rate: $sample_rate, skipping: $i" >&2
    continue
  elif ((sample_rate / 2 == 48000)) \
    || ((sample_rate / 4 == 48000)); then
    target_sample_rate=48000
  elif ((sample_rate / 2 == 44100)) \
    || ((sample_rate / 4 == 44100)); then
    target_sample_rate=44100
  elif [ -z "$force" ]; then
    echo "Unexpected sample rate: $sample_rate, skipping: $i" >&2
    continue
  fi
  target_sample_rate=${target_sample_rate:-$sample_rate}
  aformat="aformat=s16:$target_sample_rate"
  format="$aresample,$aformat"

  # Invariants: 
  # - Playback is non-subset compatible (increased maximum number of predictors from 12 to 32).
  # References:
  # - [FLAC compression levels 8 versus 12](https://hydrogenaud.io/index.php?topic=108100.0)
  # - https://xiph.org/flac/format.html#subset
  ffmpeg -i "$i" -c:a flac -compression_level 12 -filter:a "$format" -vn "$tmp_dir/${i%.*}.flac" < /dev/null

  rm "$i"
done <<< "$(find . -maxdepth 1 -type f | sed 's/^\.\///')"
mv "$tmp_dir"/*.flac ./

cat > "info.dither.txt" << EOF
Dither command:
ffmpeg -i "\$input_file" -c:a flac -compression_level 12 -filter:a "$format" -vn "\$output_file"

Versions:
$(ffmpeg -version | head -n1)
$(sox --version | sed 's/^sox:\s*//')
EOF
