#!/bin/sh

countdown=${1:-0}
if [ "$countdown" -gt 0 ]; then
  (sleep "$countdown"; killall ffmpeg >/dev/null 2>&1) &
fi
screen=$DISPLAY
if ! echo "$screen" | grep -qE \.; then
  screen="${screen}.0"
fi
geo=$(xdpyinfo | awk '/dimensions:/{print $2}')
ffmpeg \
  -f x11grab \
  -r 25 \
  -s "$geo" \
  -i "$screen" \
  -vcodec libx264 \
  -preset ultrafast \
  video.mkv
