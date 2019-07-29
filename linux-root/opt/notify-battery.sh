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

display=$(ps -aeux --no-header | \
  grep "^$user.*DISPLAY=[0-9A-Za-z:]*" | \
  sed 's/.*DISPLAY=\([0-9A-Za-z:]*\).*/\1/g' | \
  head -n1)
export DISPLAY=$display

export PATH="/bin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"

TOO_LOW=15
BATTERY_LEVEL=$(acpi -b | grep -P -o '[0-9]+(?=%)')
if [ "$BATTERY_LEVEL" -le "$TOO_LOW" ]; then
    notify-send -u critical "Battery low" "Battery level is ${BATTERY_LEVEL}%!"
fi
