#!/bin/bash

user=fn

log_dir="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
mkdir -p "$log_dir"
log_file="$log_dir/$(basename "$0")"
date '+%Y-%m-%d_%H-%M-%S' > "$log_file"
exec  > >(tee -ia "$log_file")
exec 2> >(tee -ia "$log_file" >& 2)
exec 9> "$log_file"
BASH_XTRACEFD=9

set -ex

# ||
# See: /etc/acpd/lid.sh
# display=$(ls /tmp/.X11-unix/* | sed s#/tmp/.X11-unix/X##)
display=$(ps -aeux --no-header | \
  grep "^$user.*DISPLAY=[0-9A-Za-z:]*" | \
  sed 's/.*DISPLAY=\([0-9A-Za-z:]*\).*/\1/g' | \
  head -n1)
export DISPLAY=$display

# See: https://wiki.archlinux.org/index.php/Acpid#Laptop_Monitor_Power_Off
xauthority=$(ps -C Xorg -f --no-header | \
  grep "$user" | \
  sed -n 's/.*-auth //; s/ -[^ ].*//; p')
export XAUTHORITY=$xauthority

# Declare plugged in outputs
devices=$(find /sys/class/drm/*/status)
while read -r l
do
  dir=$(dirname "$l");
  dev=$(echo "$dir" | cut -d'-' -f 2-);
  if echo "$dev" | grep -q 'HDMI'; then
    # Remove the -X- part from HDMI-X-n
    dev=HDMI${dev#HDMI-?-}
  else
    dev=$(echo "$dev" | tr -d '-')
  fi

  status=$(cat "$l");
  if echo "$status" | grep -q '^connected'; then
    declare "$dev=yes";
  fi
done <<< "$devices"

eDP1_state=(--off)
LVDS1_state=(--off)
HDMI1_state=(--off)
HDMI2_state=(--off)
VGA1_state=(--off)
if [ -n "$HDMI1" ] && [ -n "$VGA1" ]; then
  HDMI1_state=(--mode 1920x1080 --right-of VGA1 --primary)
  VGA1_state=(--mode 1920x1080 --noprimary)
elif [ -n "$HDMI1" ]; then
  HDMI1_state=(--mode 1920x1080 --primary)
elif [ -n "$HDMI2" ] && [ -n "$VGA1" ]; then
  HDMI2_state=(--mode 1920x1080 --right-of VGA1 --primary)
  VGA1_state=(--mode 1920x1080 --noprimary)
elif [ -n "$HDMI2" ]; then
  HDMI2_state=(--mode 1920x1080 --primary)
elif [ -n "$VGA1" ]; then
  VGA1_state=(--mode 1920x1080 --primary)
elif [ -n "$LVDS1" ]; then
  LVDS1_state=(--mode 1366x768 --primary)
else
  eDP1_state=(--mode 1366x768 --primary)
fi

set +e
attempts=10
while [ $attempts -gt 0 ]; do
  # Force modes update
  xrandr --query &>/dev/null

  xrandr \
    --output eDP-1 "${eDP1_state[@]}" \
    --output LVDS-1 "${LVDS1_state[@]}" \
    --output HDMI-1 "${HDMI1_state[@]}" \
    --output HDMI-2 "${HDMI2_state[@]}" \
    --output VGA-1 "${VGA1_state[@]}" 
	if [ $? -eq 0 ]; then
		break
  else
    attempts=$(($attempts - 1))
    sleep 1
  fi
done

if [ -f "/home/$user/.config/devilspie2/rules.lua" ]; then
  killall devilspie2
  sudo -u "$user" devilspie2 &disown
fi
