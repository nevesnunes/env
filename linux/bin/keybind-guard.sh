#!/usr/bin/env sh

# Block specific programs from receiving keybind

blockee=$1
keybind=$2
if [ -z "$blockee" ] || [ -z "$keybind" ]; then
  basename=$(basename "$0")
  notify-send "[$basename] Bad arguments"
  exit 1
fi

current_class=$(xprop -id "$(xdotool getwindowfocus)" | \
    awk '/WM_CLASS/{print $4}' | sed 's/"/usr/g')
if echo "$current_class" | grep -q -i -E "$blockee"; then
  # NOTHING
  exit 128
else
  xdotool key "$keybind"
fi
