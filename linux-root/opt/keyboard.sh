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

xset r rate 300 25

xkbcomp -I/home/"$user"/.xkb /home/"$user"/.xkb/keymap/keypadmagic_keymap $DISPLAY
