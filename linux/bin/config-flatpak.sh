#!/bin/sh

set -eu

for dir in "$HOME"/.var/app/*; do
    mkdir -p \
      "$dir/config" \
      "$dir/local/share/themes"
    ! [ -d "$dir/config/fontconfig" ] && \
      cp -al "$HOME/.config/fontconfig" "$dir/config/fontconfig"
    ! [ -f "$dir/config/gtkrc-2.0" ] && \
      cp -al "$HOME/.config/gtkrc-2.0" "$dir/config/gtkrc-2.0"
    ! [ -d "$dir/config/gtk-3.0" ] && \
      cp -al "$HOME/.config/gtk-3.0" "$dir/config/gtk-3.0"
    ! [ -d "$dir/local/share/themes/Adwaitix-Dark" ] && \
      cp -al "$HOME/.local/share/themes/Adwaitix-Dark" "$dir/local/share/themes/Adwaitix-Dark"
done
