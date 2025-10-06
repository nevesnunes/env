#!/usr/bin/env sh

cd "$HOME"

# echo "$XDG_CURRENT_DESKTOP" | grep -q GNOME
if command -v pcmanfm >/dev/null 2>&1; then
  exec pcmanfm
elif echo "$XDG_CURRENT_DESKTOP" | grep -q GNOME; then
  exec nautilus
else
  exec scratchpad-terminal.sh vifm
fi
