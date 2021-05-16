#!/bin/sh

# Usage:
# xdotool getactivewindow windowminimize; sleep 2; capture-window-gif.sh 'PrBoom' 10

title=$1
countdown=${2:-0}
screen=$DISPLAY
if ! echo "$screen" | grep -qE '\.'; then
  screen="${screen}.0"
fi
geo=$(xsize.sh --title "$title" --output-geometry \
  | grep 'window:' \
  | sed 's/window: \([0-9]\+\) \([0-9]\+\) \([0-9]\+\) \([0-9]\+\).*/\3x\4 +\1,\2/')

gif_file=output.gif
palette_file=$(mktemp).png
video_file=$(mktemp).mkv
cleanup() {
  err=$?
  rm -f "$palette_file" "$video_file"
  trap '' EXIT
  exit $err
}
trap cleanup EXIT INT QUIT TERM

# https://trac.ffmpeg.org/wiki/Capture/Desktop#lossless-recording
ffmpeg \
  -y \
  -f x11grab \
  -s "$(echo "$geo" | cut -d' ' -f1)" \
  -i "${screen}$(echo "$geo" | cut -d' ' -f2)" \
  -t "$countdown" \
  -c:v libx264rgb -crf 0 -preset slow \
  "$video_file"
ffmpeg \
  -y \
  -i "$video_file" \
  -vf fps=24,palettegen \
  "$palette_file"
ffmpeg \
  -y \
  -i "$video_file" \
  -i "$palette_file" \
  -filter_complex paletteuse \
  "$gif_file"
