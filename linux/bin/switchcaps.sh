#!/bin/bash

function no {
  setxkbmap -option '' -option compose:sclk
  notify "Unset CapsLock as Ctrl"
}

function yes {
  setxkbmap -option ctrl:swapcaps
  notify "Set CapsLock as Ctrl"
}

function notify {
  icon="/usr/share/icons/Adwaita/scalable/devices/input-keyboard-symbolic.svg"
  if [ -f "$icon" ]; then
      notify-send -i ${icon} "$1"
  else
      notify-send "$1"
  fi
}

function usage {
  echo "Usage: Pass y/n to set/unset"
}

while getopts "h?yn" opt; do
  case "$opt" in
  y)
    yes
    exit 0 ;;
  n)
    no
    exit 0 ;;
  h|\?)
    usage ; exit 0 ;;
  esac
done
if [ $OPTIND -eq 1 ]; then
  usage
  exit 0
fi
