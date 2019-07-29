#!/bin/sh

set -eux

if [ "$(id -u)" -eq 0 ]; then
  USER=$(logname)
  [ -d "/home/$USER" ]
fi

role=$1
[ -d "$role" ]
target=${2:-/home/$USER/}
[ -d "$target" ]
acl=${3:-$USER}

sync_cmd=rsync
echo "$acl" | grep -qi root && sync_cmd="sudo $sync_cmd"
"$sync_cmd" -uva --usermap=:"$acl" --groupmap=:"$acl" \
  ./"$role"/ "$target"
