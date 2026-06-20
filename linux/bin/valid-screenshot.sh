#!/usr/bin/env sh

set -eu

dir="/home/$USER/Pictures/Screenshots"
mkdir -p "$dir"

if command -v flameshot; then
  if [ "$#" -eq 0 ]; then
    region_path="$HOME/.cache/flameshot/flameshot/region.txt"
    tmp_region_path="/tmp/region.txt"
    if [ -f "$region_path" ]; then
      mv "$region_path" "$tmp_region_path"
      trap 'mv "$tmp_region_path" "$region_path"' EXIT INT QUIT TERM
    fi
    flameshot full
  elif [ "$#" -eq 1 ] && [ "$1" = '-a' ]; then
    flameshot gui
  else
    title="Screenshot NOT saved!"
    context="Invalid argument for flameshot: '$1'"
    notify-send "$title" "$context"
  fi
  exit $?
fi

filename="$dir/Screenshot From $(date +"%Y-%m-%d %H-%M-%S").png"

warn() {
  err=$?

  if ! [ -f "$filename" ]; then
    title="Screenshot NOT saved!"
    context="Could not find $filename"
    notify-send "$title" "$context"
  fi

  trap '' EXIT
  exit $err
}
trap warn EXIT INT QUIT TERM

if command -v gnome-screenshot; then
  # Force keyboard ungrab
  { xdotool key Scroll_Lock && xdotool key Scroll_Lock; } || true

  gnome-screenshot -f "$filename" "$@"
fi
