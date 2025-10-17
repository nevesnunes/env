#!/usr/bin/env sh

xset r rate 300 35
xset s off
xset s noblank
xset dpms 0 0 0
xdg-screensaver suspend "$(xwininfo -root | grep 'Window id:' | grep -o '0x[0-9]*')"
xkbcomp -I"$HOME/.xkb" "$HOME/.xkb/keymap/keypadmagic_keymap" "$DISPLAY"

nohup devilspie2 > /dev/null &
nohup xbindkeys > /dev/null &
