#!/usr/bin/env sh

xset r rate 300 25
xset s off
xset s noblank
xset dpms 0 0 0
xdg-screensaver suspend "$(xwininfo -root | grep 'Window id:' | grep -o '0x[0-9]*')"

go.sh -t
nohup python "$HOME"/bin/notify-logger.py &
#nohup "$HOME"/bin/user-menu/um-launcher.sh &

#nohup autocutsel &
#nohup autocutsel -selection PRIMARY &
nohup devilspie2 &
#nohup strike-alert.sh &
nohup udisksctl mount --block-device /dev/disk/by-label/FATSO &
nohup xbindkeys &

nohup /opt/mouse.sh &
nohup /opt/notify-tasks.sh &
