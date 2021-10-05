#!/bin/sh

contents_clipboard=$(xclip -selection clipboard -o)
contents_primary=$(xclip -selection primary -o)
if [ -n "$contents_primary" ]; then
  link="$contents_primary"
else
  link="$contents_clipboard"
fi

notify-send "Opening link" "$link"
exec mpv "$link"
