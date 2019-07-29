#!/usr/bin/env bash

countdown=$1
if [[ -n "$countdown" ]] && [[ "$countdown" -gt 0 ]]; then
  (sleep "$countdown"; killall ffmpeg) &>/dev/null &disown
fi

screen=$DISPLAY
if ! echo "$screen" | grep -qE \.; then
  screen+=".0"
fi
geo=$(xdpyinfo | grep -i dimensions: | sed 's/[^0-9]*pixels.*(.*).*/usr/' | sed 's/[^0-9x]*/usr/')
ffmpeg -f x11grab -r 25 -s "$geo" -i "$screen" -vcodec libx264 -preset ultrafast video.mkv
