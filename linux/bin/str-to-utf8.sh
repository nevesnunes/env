#!/usr/bin/env bash

read -r str
[ -z "$str" ] && str=$(xclip -selection primary -o)
[ -z "$str" ] && str=$(xclip -selection clipboard -o)
str_to_utf8=($(printf '%s' "$str" | \
    iconv -f utf8 -t utf32be | \
    xxd -p | \
    tr -d '\n' | \
    sed 's/.\{8\}/U& /g'))
sleep 0.2
xdotool key --clearmodifiers "${str_to_utf8[@]}"
