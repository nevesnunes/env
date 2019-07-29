#!/usr/bin/env bash

tmp="${XDG_RUNTIME_DIR:-/tmp}/$0"
mkdir -p "$tmp"

for ((i=0; i<6; i++)); do
  channel1=$(printf '%02x' $(($((i+1))*10)))
  channel2=$(printf '%02x' $(($((i+1))*20)))
  channel3=$(printf '%02x' $(($((6-i))*20)))
  color="$channel1$channel2$channel3"
  convert -size 1920x1080 xc:"#$color" "$tmp"/"$color".png
  feh "$tmp"/"$color".png &
done

desktop=$(xdotool get_desktop)
windows=$(xdotool search --desktop "$desktop" --title "" | wc -l)
while [[ $windows -lt 6 ]]; do
  sleep 0.1
  windows=$(xdotool search --desktop "$desktop" --title "" | wc -l)
done
xlayouts.sh "Digits" "222"

rm -r "$tmp"
