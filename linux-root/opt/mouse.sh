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

set -eux

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

# Mouse may have multiple ids (check with xinput)
ids=$(xinput --list | awk -v search="Mouse" \
    '$0 ~ search { \
        match($0, /id=[0-9]+/); \
        if (RSTART) \
            print substr($0, RSTART+3, RLENGTH-3) \
    }')
for i in $ids ; do
    # Side buttons work as middle click
    xinput --set-button-map "$i" 1 2 3 4 5 6 7 2 2

    # Speed boost
    #xinput set-prop $i 'Coordinate Transformation Matrix' 2.000000, 0.000000, 0.000000, 0.000000, 2.000000, 0.000000, 0.000000, 0.000000, 1.000000

    # Slower accelaration
    #xinput set-prop $i 'Device Accel Profile' -1
    #xinput set-prop $i 'Device Accel Velocity Scaling' 1
done
