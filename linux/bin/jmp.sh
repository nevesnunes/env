#!/usr/bin/env bash

geo=$(xrandr | head -n1 | cut -d, -f2 | cut -d' ' -f3-5)
w=$(echo -e "$geo" | cut -d' ' -f1)
h=$(echo -e "$geo" | cut -d' ' -f3)
half_w=$(($w / 2))
half_h=$(($h / 2))

ww=80
wh=16
half_ww=$(($ww / 2))
half_wh=$(($wh / 2))
wx=$(($half_w - $(( 11 * $half_ww)) ))
wy=$(($half_h - $(( 25 * $half_wh)) ))

user-terminal -geometry "$ww""x""$wh""+""$wx""+""$wy" \
         -bg rgb:40/40/40 \
         -title "scratchpad" \
         -e jmp
