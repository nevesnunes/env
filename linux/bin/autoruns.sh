#!/usr/bin/env sh

xset r rate 300 25
xset s off
xset s noblank
xset dpms 0 0 0
xdg-screensaver suspend "$(xwininfo -root | grep 'Window id:' | grep -o '0x[0-9]*')"

go.sh -t
#nohup python "$HOME"/bin/notify-logger.py &
#nohup strike-alert.sh &
#nohup "$HOME"/bin/user-menu/um-launcher.sh &

nohup devilspie2 &
nohup pyls --tcp --port=10777 &
nohup udisksctl mount --block-device /dev/disk/by-label/FATSO &
nohup xbindkeys &

nohup /opt/mouse.sh &
nohup /opt/notify-tasks.sh &
