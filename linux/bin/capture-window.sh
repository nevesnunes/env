#!/usr/bin/env bash

# Usage:
# wmctrl -r :ACTIVE: -b add,hidden; sleep 1; echo "y" | capture-window.sh "PrBoom"

title=$1
countdown=$2
if [[ -n "$countdown" ]] && [[ "$countdown" -gt 0 ]]; then
  (sleep "$countdown"; killall ffmpeg) &>/dev/null &disown
fi

screen=$DISPLAY
if ! echo "$screen" | grep -qE \.; then
  screen+=".0"
fi
geo="$(xsize.sh --title "$title" --output-geometry)"
ffmpeg -f x11grab -r 25 -s "$(echo "$geo" | cut -d' ' -f1)" -i "$screen"+"$(echo "$geo" | cut -d' ' -f2)" -vcodec libx264 -preset ultrafast video.mkv
