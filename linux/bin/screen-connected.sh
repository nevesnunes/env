#!/bin/sh

set -eu

screens=$(xrandr | grep -w connected)
if [ "$(echo "$screens" | wc -l)" -eq 2 ]; then
  ~/.screenlayout/dual.sh
elif echo "$screens" | grep -q HDMI-2; then
  ~/.screenlayout/hdmi2.sh
elif echo "$screens" | grep -q eDP-1; then
  ~/.screenlayout/edp1.sh
else
  exit 1
fi

killall devilspie2
nohup devilspie2 </dev/null >/dev/null 2>&1 &
