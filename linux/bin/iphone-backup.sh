#!/bin/sh

set -eux

from=${1:-$HOME/media/iphone}
to=${2:-$HOME/media/iphone-unback}

iid=$(ideviceinfo | awk '/UniqueDeviceID/ { print $2 }')
[ -n "$iid" ]

rm -rf "$to"
mkdir -p "$from" "$to"
idevicebackup2 -u "$iid" backup "$from"
ideviceunback_dir=~/opt/ideviceunback
[ -d "$ideviceunback_dir" ] || \
  git clone https://github.com/inflex/ideviceunback.git "$ideviceunback_dir"
"$ideviceunback_dir"/ideviceunback -v -i "$from/$iid/" -o "$to"
