#!/bin/sh

# Usage:
# ./$0 foo.mkv 00:00:00 00:00:06

gif_file=output.gif
palette_file=$(mktemp).png
video_file=$1
start_ts=${2:-}
duration=${3:-}
cleanup() {
  err=$?
  rm -f "$palette_file"
  trap '' EXIT
  exit $err
}
trap cleanup EXIT INT QUIT TERM

# https://trac.ffmpeg.org/wiki/Capture/Desktop#lossless-recording
ffmpeg \
  -y \
  -i "$video_file" \
  -vf fps=24,palettegen \
  "$palette_file"
if [ -n "$2" ] && [ -n "$3" ]; then
  ffmpeg \
    -y \
    -t "$duration" \
    -i "$video_file" \
    -i "$palette_file" \
    -ss "$start_ts" \
    -filter_complex paletteuse \
    "$gif_file"
else
  ffmpeg \
    -y \
    -i "$video_file" \
    -i "$palette_file" \
    -filter_complex paletteuse \
    "$gif_file"
fi
