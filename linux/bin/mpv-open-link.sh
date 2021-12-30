#!/bin/sh

script_name=$(basename "$0")

contents_clipboard=$(xclip -selection clipboard -o)
contents_primary=$(xclip -selection primary -o)
if [ -n "$contents_primary" ]; then
  link="$contents_primary"
else
  link="$contents_clipboard"
fi

icon=/usr/share/icons/hicolor/symbolic/apps/mpv-symbolic.svg
if ! echo "$link" | grep -q "://"; then
  notify-send -i "$icon" "$script_name" "Skipping: $link"
  exit 1
fi
notify-send -i "$icon" "$script_name" "Opening: $link"
exec mpv "$link"
