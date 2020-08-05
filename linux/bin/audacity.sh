#!/bin/sh

if command -v flatpak >/dev/null 2>&1 && \
    flatpak list --app | grep -qi audacity; then
  config-flatpak.sh
  exec flatpak run org.audacityteam.Audacity
else
  exec audacity "$@"
fi
