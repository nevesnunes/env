#!/bin/sh

set -eu

wm=${1:-fluxbox}

Xephyr -ac -screen 1280x900 -br -reset -terminate 2> /dev/null :3 &

# Wait for X server to be ready
inotifywait --timeout 2 /tmp/.X11-unix/

DISPLAY=:3.0 xbindkeys &
DISPLAY=:3.0 viewnior &
DISPLAY=:3.0 viewnior &
DISPLAY=:3.0 "$wm" &

echo "Press any key to kill X server..."
read -r _

killall Xephyr
