#!/usr/bin/env bash

file="$XDG_RUNTIME_DIR/bin/switchlayout.data"
keymap_file="$XDG_CONFIG_HOME/switchlayout/keymap"
mkdir -p "$(dirname "$file")"
touch "$file"

function off {
  setxkbmap us -variant intl -option ''
  notify "Unset" "CapsLock as Ctrl"

  echo "off" > "$file"
}

function on {
  if [[ -s "$keymap_file" ]] ; then
    keymap=$(head -n 1 "$keymap_file")
    xkbcomp -I$HOME/.xkb "$HOME/.xkb/keymap/$keymap" $DISPLAY
    setxkbmap "$keymap" -variant ''
    notify "Set" "CapsLock as Ctrl ($keymap)"
  else
    setxkbmap us -variant intl -option ctrl:swapcaps
    notify "Set" "CapsLock as Ctrl (us-intl)"
  fi

  echo "on" > "$file"
}

function notify {
  icon="/usr/share/icons/Adwaita/scalable/devices/input-keyboard-symbolic.svg"
  if [ -f "$icon" ]; then
    notify-send -i ${icon} "$1" "$2"
  else
    notify-send "$1" "$2"
  fi
}

if [ $# == 0 ]; then
  if [[ -s $file ]] ; then
    line=$(head -n 1 "$file")
    if [ "$line" == "off" ]; then on; else off; fi
  else
    on
  fi
fi
while [ "$1" != "" ]; do
    case $1 in
    on) on ;;
    off) off ;;
    esac
    shift
done
