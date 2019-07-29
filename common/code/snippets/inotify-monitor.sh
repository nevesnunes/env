#!/usr/bin/env bash

set -eu

SCREEN_LEFT=DP2
SCREEN_RIGHT=eDP1
START_DELAY=5

renice +19 $$ >/dev/null

sleep $START_DELAY

OLD_DUAL="dummy"

while [ 1 ]; do
    DUAL=$(cat /sys/class/drm/card0-DP-2/status)

    if [ "$OLD_DUAL" != "$DUAL" ]; then
        if [ "$DUAL" == "connected" ]; then
            echo 'Dual monitor setup'
            xrandr --output $SCREEN_LEFT --auto --rotate normal --pos 0x0 --output $SCREEN_RIGHT --auto --rotate normal --below $SCREEN_LEFT
        else
            echo 'Single monitor setup'
            xrandr --auto
        fi

        OLD_DUAL="$DUAL"
    fi

    inotifywait -q -e close /sys/class/drm/card0-DP-2/status >/dev/null
done
