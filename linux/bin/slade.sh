#!/bin/sh

if command -v flatpak >/dev/null 2>&1 && \
    flatpak list --app | grep -qi slade; then
  config-flatpak.sh
  exec flatpak run \
    --env=GTK_THEME=Adwaita:dark \
    --env=GTK2_RC_FILES="$HOME/.local/share/themes/Adwaitix-Dark/gtk-2.0/gtkrc" \
    --filesystem=host \
    net.mancubus.SLADE
else
  exec slade "$@"
fi
