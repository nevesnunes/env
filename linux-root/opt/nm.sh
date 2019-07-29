#!/bin/bash

log_dir="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
mkdir -p "$log_dir"
log_file="$log_dir/$(basename "$0")"
date '+%Y-%m-%d_%H-%M-%S' > "$log_file"
exec  > >(tee -ia "$log_file")
exec 2> >(tee -ia "$log_file" >& 2)
exec 9> "$log_file"
BASH_XTRACEFD=9

set -eux

# FIXME: Probably better to iterate /sys/bus/usb/devices/[0-9]-[0-9]/idVendor
ID=$(lsusb -t | grep Driver=ath | awk '{print $3}' | cut -d':' -f1)
USB="1-$ID"

echo "$USB" > /sys/bus/usb/drivers/usb/unbind

#modprobe -r rt2500usb
#modprobe rt2500usb

#rfkill unblock all

#DEVICE="wlp0s29f7u$ID"
#ip link set "$DEVICE" up
#nmcli dev wifi con "UNIX-OR-BUST"
#ifconfig "$DEVICE" up
#iwlist "$DEVICE" scan
#iwconfig "$DEVICE" essid "UNIX-OR-BUST"
#dhclient "$DEVICE" 

echo "$USB" > /sys/bus/usb/drivers/usb/bind
