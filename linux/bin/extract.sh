#!/usr/bin/env bash

IFS=$'\n' files=($NAUTILUS_SCRIPT_SELECTED_FILE_PATHS)
if [ -z "${files[*]}" ]; then
  files=("$@")
fi
if [ -z "${files[*]}" ]; then
  notify-send "File Manager Script" "Input was empty. Exiting..."
  exit 1
fi

for file in "${files[@]}"; do
  if type atool &>/dev/null; then
    atool -x "$file"
  else
    unrar x "$file"
  fi
done
