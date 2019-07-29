#!/usr/bin/env bash

# /usr/bin/gnome-keyring-daemon --daemonize --login
# /usr/libexec/polkit-gnome-authentication-agent-1
# /usr/libexec/gnome-settings-daemon
# /usr/libexec/udisks2/udisksd --no-debug
# /usr/libexec/gvfs-udisks2-volume-monitor
# /usr/libexec/ibus-x11 --kill-daemon

feh --bg-fill "/home/fn/Pictures/bg.jpg" 

compton &
dunst &
ibus-daemon &

user-browser &
thunderbird &

# Give time for panel to start
sleep 2

skype &
nm-applet &
