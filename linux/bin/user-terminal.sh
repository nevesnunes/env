#!/usr/bin/env sh

[ $# -eq 0 ] && exec user-terminal
if readlink "$(command -v user-terminal)" | grep -qi gnome-terminal; then
  exec user-terminal -- "${@}"
else
  exec user-terminal -e "${@}"
fi
