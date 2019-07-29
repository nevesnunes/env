#!/bin/sh

set -eu

for dir in "$HOME"/.var/app/*/; do
    cp -al "$HOME/.config/fontconfig" "$dir/config/fontconfig"
    cp -al "$HOME/.config/gtk-3.0" "$dir/config/gtk-3.0"
done
