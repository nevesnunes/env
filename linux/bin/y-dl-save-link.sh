#!/usr/usr/bin/env bash

description=$(xclip -o)
output=$((youtube-dl -o "~/Videos/%(title)s.%(ext)s" "${description}") 2>&1)

# Check download success
rc=$?; if [[ $rc != 0 ]]; then
    title="Video NOT saved!"
    description="${output}"
else
    title="Video saved!"
fi

# Display notification (with icon if available)
icon="/usr/share/icons/Adwaita/scalable/places/folder-videos-symbolic.svg"
if [ -f "$icon" ]; then
    notify-send -i ${icon} "${title}" "${description}"
else
    notify-send "${title}" "${description}"
fi
