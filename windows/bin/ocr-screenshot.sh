#!/usr/bin/env bash

if [[ "$MSYSTEM" == MINGW* ]]; then
  SCR_IMG="/c/Users/$USER/Pictures/$(ls -tr ~/Pictures/ | tail -n1)"
else
  SCR_IMG="$(mktemp).png"
  gnome-screenshot -a -f "$SCR_IMG"
fi
function cleanup {
  rm "$SCR_IMG" "$TESS_OUT.txt"
}
trap cleanup EXIT

mogrify -modulate 100,0 -resize 400% "$SCR_IMG" 

TESS_OUT="ocr_screenshot"
tesseract "$SCR_IMG" "$TESS_OUT"

echo "#### OCR result:"
cat "$TESS_OUT.txt"
xclip -selection clipboard -i < "$TESS_OUT.txt"
xclip -selection primary -i < "$TESS_OUT.txt"
