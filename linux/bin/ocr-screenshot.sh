#!/bin/sh

set -eux

SCR_IMG="$(mktemp)"
trap 'rm $SCR_IMG*' EXIT

gnome-screenshot -a -f "$SCR_IMG.png"
mogrify -modulate 100,0 -resize 400% "$SCR_IMG.png" 
tesseract "$SCR_IMG.png" "$SCR_IMG" >/dev/null 2>&1

cat "$SCR_IMG.txt"

xclip -selection clipboard -i < "$SCR_IMG.txt"
xclip -selection primary -i < "$SCR_IMG.txt"

icon=/usr/share/icons/Adwaita/scalable/mimetypes/x-office-document-symbolic.svg
notify-send -i "$icon" 'OCR done!' 'OCR results copied to clipboard'
