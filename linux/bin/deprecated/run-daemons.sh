#!/usr/bin/env sh

# DEPRECATED: systemd handles these services

/usr/bin/gnome-keyring-daemon --daemonize --login
/usr/libexec/polkit-gnome-authentication-agent-1
/usr/libexec/gnome-settings-daemon
/usr/libexec/udisks2/udisksd --no-debug
/usr/libexec/gvfs-udisks2-volume-monitor
/usr/libexec/ibus-x11 --kill-daemon
