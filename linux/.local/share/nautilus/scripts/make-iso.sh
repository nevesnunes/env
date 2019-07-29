#!/usr/bin/env bash

files=$NAUTILUS_SCRIPT_SELECTED_FILE_PATHS
if [ -z "$files" ]; then
  notify-send "Nautilus" "Input was empty. Exiting..."
  exit 1
fi

exec mkisofs -r -N -allow-leading-dots -d -J -o w.iso "$files"
