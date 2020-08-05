#!/bin/sh

set -eux

iid=$(ideviceinfo | awk '/UniqueDeviceID/ { print $2 }')
[ -n "$iid" ]

rm -rf ~/media/iphone-unback
mkdir -p ~/media/iphone ~/media/iphone-unback
idevicebackup2 -u "$iid" backup ~/media/iphone
ideviceunback_dir=~/opt/ideviceunback
[ -d "$ideviceunback_dir" ] || \
  git clone https://github.com/inflex/ideviceunback.git "$ideviceunback_dir"
"$ideviceunback_dir"/ideviceunback -v -i ~/media/iphone/"$iid"/ -o ~/media/iphone-unback/
