#!/usr/bin/env bash

# Force keyboard ungrab
session=$(wmctrl -m | head -n1 | awk '{print $2}')
if ! echo "$session" | grep -q -i "GNOME"; then
  #xdotool key Escape
  xdotool key Scroll_Lock && xdotool key Scroll_Lock
fi

cmd=(gnome-screenshot --remove-border)
args=()
using_shutter=0
while [ $# -gt 0 ]; do
  case $1 in
    shutter)
      cmd=(shutter --disable_systray --exit_after_capture --no_session --min_at_startup)
      using_shutter=1
      killall -9 shutter
      ;;
    -a)
      if [ $using_shutter -gt 0 ]; then
        args+=("--select")
      else
        args+=("-a")
      fi
      ;;
    *)
      args+=("$1")
  esac
  shift
done
if [ ${#args[@]} -eq 0 ] && [ $using_shutter -gt 0 ]; then
  args+=("--full")
fi
volume=$(amixer sget Master | awk -F '[],[,%]'  '/%/{print $2; exit}')
amixer sset Master 0
"${cmd[@]}" "${args[@]}"
amixer sset Master "$volume"%
if [ $using_shutter -gt 0 ]; then
  exit 0
fi

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
