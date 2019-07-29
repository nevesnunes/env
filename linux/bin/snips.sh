#!/bin/bash

SHRUG="¯\_(ツ)_/¯"
TMPFILE=$(mktemp)

xclip -o > "$TMPFILE"
echo -e $SHRUG | xclip -selection clipboard
xdotool key --clearmodifiers Ctrl+V
xclip -selection clipboard < "$TMPFILE" 
rm "$TMPFILE"
