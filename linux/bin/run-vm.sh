#!/usr/bin/env bash

set -ex

vm=$1
if [ -z "$vm" ]; then
  echo "No VM provided."
  exit 1
fi
mode=$(printf "640x480\n1024x768\n1920x1080" | fzf)
if [ -z "$mode" ]; then
  echo "No mode provided."
  exit 1
fi

# Declare plugged in outputs
devices=$(find /sys/class/drm/*/status)
while read -r l
do
  dir=$(dirname "$l")
  dev=$(echo "$dir" | cut -d'-' -f 2-)
  if echo "$dev" | grep -q 'HDMI'; then
    # Remove the -X- part from HDMI-X-n
    dev=HDMI${dev#HDMI-?-}
  else
    dev=$(echo "$dev" | tr -d '-')
  fi

  status=$(cat "$l")
  if echo "$status" | grep -q '^connected'; then
    declare "$dev=yes";
    break
  fi
done <<< "$devices"
if [ -n "$HDMI1" ]; then
  monitor=HDMI-1
elif [ -n "$HDMI2" ]; then
  monitor=HDMI-2
elif [ -n "$VGA1" ]; then
  monitor=VGA-1
elif [ -n "$LVDS1" ]; then
  monitor=LVDS-1
elif [ -n "$eDP1" ]; then
  monitor=eDP-1
else
  echo "No output provided."
  exit 1
fi

original_resolution=$(xrandr -q | sed -n 's/.*current[ ]\([0-9]*\) x \([0-9]*\),.*/\1x\2/p')
cleanup() {
  switchlayout.sh on
  xrandr --output "$monitor" --mode "$original_resolution"
}
trap 'cleanup' EXIT HUP INT QUIT TERM

switchlayout.sh off
xrandr --output "$monitor" --mode "$mode"

runner=/usr/lib64/virtualbox/VirtualBoxVM
if [ -x "$runner" ]; then
  "$runner" --startvm "$vm" --fullscreen
else
  virtualbox --startvm "$vm" --fullscreen
fi
