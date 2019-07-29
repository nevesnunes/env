#!/usr/bin/env bash

# Force keyboard ungrab
session=$(wmctrl -m | head -n1 | awk '{print $2}')
if ! echo "$session" | grep -q -i "GNOME"; then
  #xdotool key Escape
  xdotool key Scroll_Lock && xdotool key Scroll_Lock
fi

gnome-screenshot "$@"

# Compute dates, accounting for possible change in minute or hour
prefix="*$(date +%Y-%m-%d) "
prefix_now="$prefix$(date +%H-%M-)"
prefix_before="$prefix$(date -d 'now - 5 seconds' +%H-%M-)"
second="$(date +%S)"

# Command may finish before pattern date is generated,
# therefore we will test filenames matching a certain delay
delay=$((10#$second - 5))

# Seconds are positive
if [[ $delay -le 0 ]]; then
    delay=0
fi

# Iterate through our delay interval
dir="/home/$USER/Pictures"
for i in $(seq -f "%02g" $delay "$second"); do
    pattern_now="$prefix_now$i*"
    pattern_before="$prefix_before$i*"
    filename=$(find "$dir" -maxdepth 1 -type f -name "$pattern_now" -o \
       -name "$pattern_before")

    if [[ -n $filename ]]; then
        exit 0
    fi
done

# No screenshot found, display notification
title="Screenshot NOT saved!"
sample="No matching filename found..."
icon="/usr/share/icons/Adwaita/scalable/places/folder-pictures-symbolic.svg"
if [[ -f $icon ]]; then
    notify-send -i ${icon} "${title}" "${sample}"
else
    notify-send "${title}" "${sample}"
fi
