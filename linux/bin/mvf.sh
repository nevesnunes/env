#!/usr/bin/env bash

source "$HOME/bin/bin-choosers.sh"
source "$HOME/bin/bin-utils.sh"

IFS=$'\n' files=($NAUTILUS_SCRIPT_SELECTED_FILE_PATHS)
if [ -z "${files[*]}" ]; then
  files=("$@")
fi
if [ -z "${files[*]}" ]; then
  read -r -n1 -p "Input was empty. Exiting..."
  exit 1
fi

dir=""
for i in "${files[@]}"; do
  name=$(basename "$i")

  # Assuming all files are of the same type
  if [[ "$dir" == "" ]]; then
    mime=$(xdg-mime query filetype "$name")
    if [[ -n $(match "$mime" "image") ]] ||
        [[ -n $(match "$mime" "video") ]]; then
      dir="$(choose_image_location)"
    else
      dir="$(choose_location)"
    fi
  fi

  "$HOME/bin/mv-file-fuzzy.sh" -d "$dir" "$name"
done
