#!/usr/bin/env sh

set -eu

dir="/home/$USER/Pictures/Screenshots"
mkdir -p "$dir"
filename="$dir/Screenshot From $(date +"%Y-%m-%d %H-%M-%S")"

warn() {
  err=$?

  if ! [ -f "$filename" ]; then
    icon="/usr/share/icons/Adwaita/scalable/places/folder-pictures.svg"
    title="Screenshot NOT saved!"
    context="Could not find $filename"
    if [ -f $icon ]; then
      notify-send -i $icon "$title" "$context"
    else
      notify-send "$title" "$context"
    fi
  fi

  trap '' EXIT
  exit $err
}
trap warn EXIT INT QUIT TERM

# Force keyboard ungrab
{ xdotool key Scroll_Lock && xdotool key Scroll_Lock; } || true

gnome-screenshot -f "$filename" "$@"
