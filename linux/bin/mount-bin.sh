#!/usr/bin/env bash

# With partition table:
# https://serverfault.com/questions/296160/how-to-mount-a-bin-image-file-in-linux

set -eu

name=$1

[ -f "$name".cue ] && ! [ -f "$name".cue.backup ] && \
    cp "$name".cue "$name".cue.backup
cp ~/code/snippets/recipes/cue "$name".cue
sed -i -e "s/%%%/$name/g" "$name".cue

! [ -f "$name".iso ] && \
    bchunk "$name".bin "$name".cue "$name".iso

mdkir -p ~/tmp/cdrom
sudo mount -o loop "$name".iso ~/tmp/cdrom/
