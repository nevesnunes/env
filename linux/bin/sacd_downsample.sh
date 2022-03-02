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
  # - 176.4KHz to 88.2KHz
  # - 192KHz to 96KHz
  sample_rate=$(ffprobe -show_streams -select_streams a:0 "$i" 2> /dev/null \
    | grep sample_rate= \
    | grep -o '[0-9]\+')
  if ((sample_rate <= 48000 * 2)) && [ -z "$force" ]; then
    echo "Already in target sample rate: $sample_rate, skipping: $i" >&2
    continue
  elif ((sample_rate / 2 == 48000 * 2)) \
    || ((sample_rate / 4 == 48000 * 2)) \
    || ((sample_rate / 8 == 48000 * 2)); then
    target_sample_rate=$((48000 * 2))
  elif ((sample_rate / 2 == 44100 * 2)) \
    || ((sample_rate / 4 == 44100 * 2)) \
    || ((sample_rate / 8 == 44100 * 2)); then
    target_sample_rate=$((44100 * 2))
  elif [ -z "$force" ]; then
    echo "Unexpected sample rate: $sample_rate, skipping: $i" >&2
    continue
  fi
  target_sample_rate=${target_sample_rate:-$sample_rate}
  aformat="aformat=s32:$target_sample_rate"

  # FIXME:
  # Super Audio CD System Description - Part 2, Audio Specification - E.2 Analog Post-filter 
  # > To protect analog amplifiers and loudspeakers, it is recommended that a Super Audio CD player contain at its output an analog low pass filter with a cut-off frequency of maximum 50 kHz and a slope of minimum 30 dB/Oct. For use with wide-band audio equipment, filters with a cut-off frequency of over 50 kHz can be used.
  sox -S "$i" --compression 8 "$tmp_sox_dir/$i" sinc -$((target_sample_rate / 2 - 8000)) -t 20k
  ffmpeg -nostdin -i "$tmp_sox_dir/$i" -af "$aformat" "$tmp_ffmpeg_dir/$i"

  rm "$tmp_sox_dir/$i"
  rm "$i"
  mv "$tmp_ffmpeg_dir/$i" .
done <<< "$(find . -maxdepth 1 -type f | sed 's/^\.\///')"

cat > "info.downsample.txt" << EOF
Downsample command:
sox -S "\$input_file" --compression 8 "\$tmp_sox_dir/\$input_file" sinc -$((target_sample_rate / 2 - 8000)) -t 20k
ffmpeg -nostdin -i "\$tmp_sox_dir/\$input_file" -af "$aformat" "\$output_file"

Versions:
$(ffmpeg -version | head -n1)
$(sox --version | sed 's/^sox:\s*//')
EOF
