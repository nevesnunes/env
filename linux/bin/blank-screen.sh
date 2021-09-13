#!/bin/sh

# Avoid activation from keyboard input
sleep 1

# Bug: May unblank after a while
# - https://bugs.launchpad.net/ubuntu/+source/gnome-power-manager/+bug/447728
# Alternative (also affected):
# dbus-send --session --dest=org.gnome.Shell --print-reply --type=method_call /org/gnome/Shell org.gnome.Shell.Eval string:'Main.screenShield.activate(true);'
exec xset dpms force off
