#!/bin/sh

set -eu

info=$(isoinfo -d -i /dev/sr0)
# ||
# isosize -x /dev/sr0
bs=$(echo "$info" | grep -i 'block size'  | grep -oE '[0-9]*')
[ -n "$bs" ]
vs=$(echo "$info" | grep -i 'volume size' | grep -oE '[0-9]*')
[ -n "$vs" ]
dd if=/dev/sr0 of="$PWD/out.iso" bs="$bs" count="$vs"
