#!/usr/bin/env sh

set -eux

[ -f "$1" ]

trap 'rm "$fg_img"' EXIT QUIT INT TERM

bg_img=$HOME/Pictures/000000.png
[ -f "bg_img" ] || \
    convert -size 640x480 xc:#000000 "$bg_img"

fg_img="$1.png"
ffmpeg -i "$1" -filter_complex "showwavespic=s=640x480:colors=white" -frames:v 1 "$fg_img"

out_dir="./waveforms"
mkdir -p "$out_dir"
convert "$bg_img" "$fg_img" -gravity center -compose over -composite "$out_dir/$fg_img"
