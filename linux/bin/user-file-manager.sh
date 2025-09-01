#!/usr/bin/env sh

if echo "$XDG_CURRENT_DESKTOP" | grep -q GNOME; then
  exec nautilus
else
  exec pcmanfm
fi
