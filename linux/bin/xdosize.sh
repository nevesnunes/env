#!/bin/bash

wh=$(xrandr | head -n1 | cut -d, -f2 | cut -d' ' -f3-5)
w=$(echo -e $wh | cut -d' ' -f1)
h=$(echo -e $wh | cut -d' ' -f3)
half_w=$(($w / 2))
half_h=$(($h * 45 / 100))
while getopts "hjkl" opt; do
    case "$opt" in
    h)
        xdotool getactivewindow windowsize $half_w $half_h
        xdotool getactivewindow windowmove 0 0
        ;;
    j)
        xdotool getactivewindow windowsize $w $half_h
        xdotool getactivewindow windowmove 0 $half_w
        ;;
    k)
        xdotool getactivewindow windowsize $w $half_h
        xdotool getactivewindow windowmove 0 0
        ;;
    l)
        xdotool getactivewindow windowsize $half_w $half_h
        xdotool getactivewindow windowmove $half_w 0
        ;;
    esac
done
