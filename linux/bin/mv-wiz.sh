#!/usr/bin/env bash

source bin-utils.sh

state="$HOME/bin/file-wiz.data"
find . -maxdepth 1 -type f \( \
        -iname "*.bmp" \
        -o -iname "*.gif" \
        -o -iname "*.jpg" \
        -o -iname "*.jpeg" \
        -o -iname "*.png" \
        -o -iname "*.svg" \
        -o -iname "*.txt" \
        -o -iname "*.pdf" \
        -o -iname "*.html" \
        \) -exec basename {} \; > "$state"
while IFS='' read -r line || [[ -n "$line" ]]; do
    clear
    echo "####"
    echo "#### $line"
    echo "####"
    printf "\n"
  
    mime=$(xdg-mime query filetype "$line")
    if [[ -n $(match "$mime" "application/pdf") ]]; then
        pdftotext "$line" - | head -n 30 | cut -c-80
    elif [[ -n $(match "$mime" "application/x-extension-html") ]]; then
        w3m -dump -T text/html "$line" | head -n 30 | cut -c-80
    elif [[ -n $(match "$mime" "image/") ]]; then
        timeout 3 viewnior "$line"
    else
        head -n 30 "$line" | cut -c-80
    fi
    printf "\n"

    # Must redirect to tty due to prompting inside read loop
    (mv-file-fuzzy.sh "$line") </dev/tty
  
    printf "\n"
done < "$state"

rm "$state"
