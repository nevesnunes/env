#!/usr/bin/env sh

# /usr/bin/gnome-keyring-daemon --daemonize --login
# /usr/libexec/polkit-gnome-authentication-agent-1
# /usr/libexec/gnome-settings-daemon
# /usr/libexec/udisks2/udisksd --no-debug
# /usr/libexec/gvfs-udisks2-volume-monitor
# /usr/libexec/ibus-x11 --kill-daemon

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
