#!/usr/bin/env sh

if command -v feh >/dev/null 2>&1; then
  feh --bg-fill "/home/fn/Pictures/bg.jpg" 
elif command -v fbsetroot >/dev/null 2>&1; then
  fbsetroot -solid "#446666"
else
  xsetroot -solid "#446666"
fi

compton &
dunst &

systemctl --user start ibus-daemon
systemctl --user start nm-applet
