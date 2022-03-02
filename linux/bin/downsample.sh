#!/usr/bin/env bash

# Reduces sample rate by applying a low-pass filter without dithering. To also convert bit rate, use `./dither.sh`.

set -eux

force=
while [ $# -gt 0 ]; do
  case $1 in
  --force | -f) force=1 ;;
  esac
  shift
done

tmp_sox_dir=$(mktemp -d)
[ -d "$tmp_sox_dir" ]
tmp_ffmpeg_dir=$(mktemp -d)
[ -d "$tmp_ffmpeg_dir" ]
trap 'rm -rf "$tmp_sox_dir" "$tmp_ffmpeg_dir"' EXIT QUIT INT TERM

while read -r i; do
  if ! file --mime-type "$i" | grep -qi '\(audio\|octet-stream\)'; then
    continue
  fi

  if head -c 3 "$i" | grep -q 'DSD'; then
    ffmpeg -nostdin -i "$i" "${i%.*}.flac"
    rm "$i"
    i=${i%.*}.flac
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
    || ((sample_rate / 4 == 48000)) \
    || ((sample_rate / 8 == 48000)); then
    target_sample_rate=48000
  elif ((sample_rate / 2 == 44100)) \
    || ((sample_rate / 4 == 44100)) \
    || ((sample_rate / 8 == 44100)); then
    target_sample_rate=44100
  elif [ -z "$force" ]; then
    echo "Unexpected sample rate: $sample_rate, skipping: $i" >&2
    continue
  fi
  target_sample_rate=${target_sample_rate:-$sample_rate}
  aformat="aformat=s32:$target_sample_rate"

  sox -S "$i" --compression 8 "$tmp_sox_dir/$i" sinc -$((target_sample_rate / 2 - 1000)) -t 4k
  ffmpeg -nostdin -i "$tmp_sox_dir/$i" -af "$aformat" "$tmp_ffmpeg_dir/$i"

  rm "$i"
  mv "$tmp_ffmpeg_dir/$i" .
done <<< "$(find . -maxdepth 1 -type f | sed 's/^\.\///')"

cat > "info.downsample.txt" << EOF
Downsample command:
sox -S "\$input_file" --compression 8 "\$tmp_sox_dir/\$input_file" sinc -$((target_sample_rate / 2)) -t 4k
ffmpeg -nostdin -i "\$tmp_sox_dir/\$input_file" -af "$aformat" "\$output_file"

Versions:
$(ffmpeg -version | head -n1)
$(sox --version | sed 's/^sox:\s*//')
EOF
