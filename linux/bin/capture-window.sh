#!/bin/sh

# Usage:
# xdotool getactivewindow windowminimize; sleep 2; echo 'y' | capture-window.sh 'PrBoom'

title=$1
countdown=${2:-0}
if [ "$countdown" -gt 0 ]; then
  (sleep "$countdown"; killall ffmpeg >/dev/null 2>&1) &
fi
screen=$DISPLAY
if ! echo "$screen" | grep -qE '\.'; then
  screen="${screen}.0"
fi
geo=$(xsize.sh --title "$title" --output-geometry | \
  grep 'window:' | \
  sed 's/window: \([0-9]\+\) \([0-9]\+\) \([0-9]\+\) \([0-9]\+\).*/\3x\4 +\1,\2/')
ffmpeg \
  -f x11grab \
  -r 25 \
  -s "$(echo "$geo" | cut -d' ' -f1)" \
  -i "${screen}$(echo "$geo" | cut -d' ' -f2)" \
  -vcodec libx264 \
  -preset ultrafast \
  video.mkv
