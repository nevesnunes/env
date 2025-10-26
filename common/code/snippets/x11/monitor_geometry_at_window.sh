#!/usr/bin/env bash

# Reference: https://superuser.com/questions/603528/how-to-get-the-current-monitor-resolution-or-monitor-name-lvds-vga1-etc

# Get the window position
eval "$(xdotool getmouselocation --shell)"

# Loop through each screen and 
# compare the offset with the window coordinates.
offset_regex="\+([-0-9]+)\+([-0-9]+)"
while read -r name width height xoff yoff; do
  if [ "${X}" -ge "$xoff" ] \
    && [ "${Y}" -ge "$yoff" ] \
    && [ "${X}" -lt "$(($xoff + $width))" ] \
    && [ "${Y}" -lt "$(($yoff + $height))" ]; then
    current_width=$width
    current_height=$height
    current_monitor=$name
  fi
done < <(xrandr \
  | grep -w connected \
  | sed -r "s/^([^ ]*).*\b([-0-9]+)x([-0-9]+)$offset_regex.*$/\1 \2 \3 \4 \5/" \
  | sort -nk4,5)

# If we found a monitor, echo it out, otherwise print an error.
if [ -n "$current_monitor" ]; then
  echo "${current_width}x${current_height}"
  exit 0
else
  exit 1
fi
