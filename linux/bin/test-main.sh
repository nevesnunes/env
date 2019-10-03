#!/usr/bin/env bash

wm=${1:-fluxbox}

Xephyr -ac -screen 1280x1024 -br -reset -terminate 2> /dev/null :3 &

# Wait for X server to be ready
inotifywait --timeout 2 /tmp/.X11-unix/

DISPLAY=:3.0 xbindkeys &
DISPLAY=:3.0 viewnior.sh &
DISPLAY=:3.0 viewnior.sh &
DISPLAY=:3.0 "$wm" &

echo "Press any key to kill X server..."
read -r -n 1

killall Xephyr
