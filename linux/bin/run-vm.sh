#!/usr/bin/env bash

set -ex

vm=$1
if [ -z "$vm" ]; then
  echo "No VM provided."
  exit 1
fi
shift
mode=$1
if [ -z "$mode" ]; then
  mode=$(printf "640x480\n1024x768\n1366x768\n1920x1080" | fzf)
fi
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

  if grep -q '^connected' "$l"; then
    declare "$dev=yes";
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

original_resolution=$(xrandr | sed -n 's/'"$monitor"' connected \?[a-z]* \([0-9]*\)x\([0-9]*\).*/\1x\2/p')
if [ -z "$original_resolution" ]; then
  # FIXME: Sums widths in multi-monitor layouts
  original_resolution=$(xrandr -q | sed -n 's/.* current \([0-9]*\) x \([0-9]*\),.*/\1x\2/p')
fi
if [ -z "$original_resolution" ]; then
  echo "No resolution detected."
  exit 1
fi

cleanup() {
  err=$?
  xrandr --output "$monitor" --mode "$original_resolution"
  trap '' EXIT
  exit $err
}
trap cleanup EXIT INT QUIT TERM

xrandr --output "$monitor" --mode "$mode"

runner=virtualbox
if command -v virtualboxvm >/dev/null 2>&1; then
  runner=virtualboxvm
fi
env QT_STYLE_OVERRIDE=adwaita-dark "$runner" --startvm "$vm" --fullscreen
