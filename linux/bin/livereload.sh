#!/usr/bin/env bash

# Usage:
# ls -d * | entr livereload.sh <action> /_
while [ "$1" != "" ]; do
  case $1 in
  browser)
    shift
    if [ -n "$1" ]; then
      app="$1"
    else
      browser=$(xdg-mime query default x-scheme-handler/http)
      if echo "$browser" | grep -q -i "firefox"; then
        app="firefox"
      else
        app="google-chrome"
      fi
    fi
    xdotool search --onlyvisible --class "$app" \
        key --window %@ 'ctrl+r'
    ;;
  image|picture)
    xdotool search --onlyvisible --class viewnior \
        key --window %@ l
    ;;
  man)
    shift
    MANPAGER="less -FX" man -l "$1"
    ;;
  *)
    echo "Unrecognized option: $1"
    exit 1
  esac
  shift
done
