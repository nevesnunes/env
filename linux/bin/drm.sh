#!/bin/sh
# shellcheck disable=SC2009

set -eu

user=$(id -n -u 1000)

# See: /etc/acpd/lid.sh
# display=$(ls /tmp/.X11-unix/* | sed s#/tmp/.X11-unix/X##)
display=$(ps -aeux --no-header | \
  grep "^$user.*DISPLAY=[0-9A-Za-z:]*" | \
  sed 's/.*DISPLAY=\([0-9A-Za-z:]*\).*/\1/g' | \
  head -n1)
export DISPLAY="$display"

# See: https://wiki.archlinux.org/index.php/Acpid#Laptop_Monitor_Power_Off
xauthority=$(ps -C Xorg -f --no-header | \
  grep "$user" | \
  sed -n 's/.*-auth //; s/ -[^ ].*//; p')
export XAUTHORITY="$xauthority"

if [ "$(id -u)" -eq 0 ]; then
  su - "$user" -s "${SHELL:-/bin/sh}"
fi

# Force modes update
xrandr --query >/dev/null 2>&1

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

if [ -f "$HOME/.config/devilspie2/rules.lua" ]; then
  killall devilspie2
  nohup devilspie2 </dev/null >/dev/null 2>&1 &
fi
