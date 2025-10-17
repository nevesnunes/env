#!/usr/bin/env sh

if ! command -v user-terminal > /dev/null; then
  for app in gnome-terminal uxterm urxvt; do
    cmd=$(command -v "$app")
    if [ -x "$cmd" ]; then
      ln -s "$cmd" ~/bin/user-terminal
      break
    fi
  done
fi

[ $# -eq 0 ] && exec user-terminal
# Interactive shell is required for 256 colors
if command -v user-terminal | xargs -n1 readlink | grep -qi gnome-terminal; then
  exec user-terminal -- "$SHELL" -ci -- "${@}"
else
  exec user-terminal -e "$SHELL" -ci -- "${@}"
fi
