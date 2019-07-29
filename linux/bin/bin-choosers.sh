#!/usr/bin/env bash

source ~/.fzf.bash
source ~/bin/bin-colors.sh

command -v bfs > /dev/null 2>&1
if [[ $? -eq 1 ]]; then
  finder="find"
else
  finder="bfs"
fi

function run_fzf {
  local dir=$1
  local location
  location=$("$finder" "$dir" \
      -maxdepth 3 -not -path "*/\\.*" -type d | fzf \
      --prompt="find in directory: ")

  if [[ $? -gt 128 ]]; then
    echo ""
  fi

  local result
  result=$("$finder" "$location" -maxdepth 6 -type d | fzf \
      --preview "ls {}" --preview-window down:10 --color border:7)

  # Add path to cache for further calls
  if [[ -d "$result" ]] && \
      ! grep -Fxq "$result" "$recent_locations_filename"; then 
    echo "$result" >> "$recent_locations_filename"

    # Rotate cache
    count_lines=$(wc -l "$recent_locations_filename" | cut -d' ' -f1)
    if [[ "$count_lines" -gt 10 ]]; then
      sed -i '1d' "$recent_locations_filename"
    fi
  fi

  echo "$result"
}

function choose_location {
  descriptions=()
  commands=()
  descriptions+=("search home   (fzf)")
  commands+=("fzf_home")
  descriptions+=("search mounts (fzf)")
  commands+=("fzf_run")
  descriptions+=("edit          (vim)")
  commands+=("edit")
  descriptions+=("art           (Pictures/2draw/txt)")
  commands+=("$HOME/Pictures/2draw/txt")
  descriptions+=("clever        (Pictures/themes/clever/txt)")
  commands+=("$HOME/Pictures/themes/clever/txt")
  descriptions+=("code          (code/snippets/txt)")
  commands+=("$HOME/code/snippets/txt")
  descriptions+=("computers     (Pictures/computers/txt)")
  commands+=("$HOME/Pictures/computers/txt")
  descriptions+=("games         (Pictures/games/txt)")
  commands+=("$HOME/Pictures/games/txt")
  descriptions+=("humour        (Documents/humour)")
  commands+=("$HOME/Documents/humour")
  descriptions+=("ui            (Pictures/ui/txt)")
  commands+=("$HOME/Pictures/ui/txt")
  descriptions+=("skip          (-.-)")
  commands+=("skip")

  recent_locations_filename="$HOME/.cache/bin-choosers.cache"
  touch "$recent_locations_filename"

  # Clean invalid directories from cache
  lines=($(IFS=$'\n' cat "$recent_locations_filename"))
  size=${#lines[@]}
  for (( i=0; i<$size; i++ )); do
    line="${lines[$i]}"
    if [[ -d "$line" ]] ; then
      descriptions+=("$line")
      commands+=("$line")
    else
      sed -i "$((i+1))d" "$recent_locations_filename"
    fi
  done

  # Read option
  PS3=$'\n'"${fg_magenta}${bold}Choose location:${reset} "
  COLUMNS=1
  select opt in "${descriptions[@]}"
  do
    size=${#descriptions[@]}
    for (( i=0; i<$size; i++ )); do
      if [[ $opt == "${descriptions[$i]}" ]] ; then
        result="${commands[$i]}"
        break
      fi
    done
    
    # Retry on bad option
    if [ -z "$result" ]; then
      (echo "Bad option.") >/dev/tty
    else
      break
    fi
  done
  unset COLUMNS
      
  if [[ "$result" == "skip" ]] ; then
    result=""
  elif [[ "$result" == "fzf_home" ]] ; then
    result=$(run_fzf "$HOME")
  elif [[ "$result" == "fzf_run" ]] ; then
    result=$(run_fzf "/run/media/$USER")
  fi

  echo "$result"
}
export -f choose_location

function choose_image_location { 
  choose_location "$*"
}
export -f choose_image_location
