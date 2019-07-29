#!/usr/usr/bin/env bash

arg="$@"
filename="$HOME/Videos/$(date +%s)"

# Notify start
icon="/usr/share/icons/Adwaita/scalable/places/folder-videos-symbolic.svg"
title="Video to fetch:"
description="$arg"
if [ -f "$icon" ]; then
    notify-send -i ${icon} "${title}" "${description}"
else
    notify-send "${title}" "${description}"
fi

/usr/bin/mpv --stream-dump="$filename" --profile=pseudo-gui -- "$@"

# Notify end
title="Video saved!"
description="$arg"
if [ -f "$icon" ]; then
    notify-send -i ${icon} "${title}" "${description}"
else
    notify-send "${title}" "${description}"
fi
