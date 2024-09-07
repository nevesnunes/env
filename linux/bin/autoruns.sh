#!/usr/bin/env sh

xset r rate 300 25
xset s off
xset s noblank
xset dpms 0 0 0
xdg-screensaver suspend "$(xwininfo -root | grep 'Window id:' | grep -o '0x[0-9]*')"
xkbcomp -I$HOME/.xkb /home/fn/.xkb/keymap/keypadmagic_keymap $DISPLAY

#go.sh -t
#nohup python "$HOME"/bin/notify-logger.py &
#nohup strike-alert.sh &
#nohup udisksctl mount --block-device /dev/disk/by-label/FATSO &

nohup devilspie2 &
nohup xbindkeys &

nohup /opt/keyboard.sh &
nohup /opt/mouse.sh &
