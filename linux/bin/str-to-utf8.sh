str_to_utf8=($(echo -en "$(xclip -selection primary -o)" | \
    iconv -f utf8 -t utf32be | \
    xxd -p | \
    tr -d '\n' | \
    sed 's/.\{8\}/U& /g'))
sleep 0.2
xdotool key --clearmodifiers "${str_to_utf8[@]}"
