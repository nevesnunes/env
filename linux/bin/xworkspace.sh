#!/bin/sh

set -eu

# Check dependecies
script_name=$(basename "$0")
for i in xdotool wmctrl; do
  command -v "$i" > /dev/null 2>&1
  if [ $? -eq 1 ]; then
    notify-send "[$script_name] Error" "$i not in \$PATH."
    exit 1
  fi
done

# Get the last occupied workspace
number='^[0-9]\+$'
target=0
workspaces=$(wmctrl -l | awk '{print $2}' | sort -u)
set -f; IFS='
'
for workspace in $workspaces; do
  set +f; unset IFS
  if echo "$workspace" | grep -q "$number"; then
    echo "$workspace"
    if [ "$workspace" -gt $target ]; then
      # Use intermediate workspace, if next one in list
      # doesn't match next expected number
      if [ "$workspace" -gt $(($target + 1)) ]; then
        break
      else
        target=$workspace
      fi
    fi
  fi
done
set +f; unset IFS

# Use the closest next free workspace
target=$(($target + 1))

# If no free workspace was found, default to last one
if [ $target -eq "$(xdotool get_num_desktops)" ]; then
  target=$(($target - 1))
fi

while [ $# -gt 0 ]; do
  case $1 in
  -t|--target)
    shift
    if echo "$1" | grep -q "$number"; then
      target=$1
    else
      notify-send "[$script_name] Error" "Invalid argument."
      exit 1
    fi
    ;;
  -m|--move-window)
    window_id="$(xdotool getactivewindow)"
    wmctrl -i -r "$window_id" -t "$target"
    wmctrl -s "$target"
    ;;
  -s|--send-window)
    window_id="$(xdotool getactivewindow)"
    wmctrl -i -r "$window_id" -t "$target"
    ;;
  -g|--goto)
    wmctrl -s "$target"
    ;;
  -i|--previous)
    target=$(( $(xdotool get_desktop) - 1))
    if [ $target -ge 0 ]; then
      wmctrl -s "$target"
    fi
    ;;
  -u|--next)
    target=$(( $(xdotool get_desktop) + 1))
    if [ $target -lt "$(xdotool get_num_desktops)" ]; then
      wmctrl -s "$target"
    fi
    ;;
  -I|--move-window-to-previous)
    target=$(( $(xdotool get_desktop) - 1))
    if [ $target -ge 0 ]; then
      window_id="$(xdotool getactivewindow)"
      wmctrl -i -r "$window_id" -t "$target"
      sleep 0.1
      wmctrl -s "$target"
      wmctrl -a "$window_id"
    fi
    ;;
  -U|--move-window-to-next)
    target=$(( $(xdotool get_desktop) + 1))
    if [ $target -lt "$(xdotool get_num_desktops)" ]; then
      window_id="$(xdotool getactivewindow)"
      wmctrl -i -r "$window_id" -t "$target"
      sleep 0.1
      wmctrl -s "$target"
      wmctrl -a "$window_id"
    fi
    ;;
  esac
  shift
done
