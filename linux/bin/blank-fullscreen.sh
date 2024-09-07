#!/bin/sh

set -eu

while [ $# -gt 0 ]; do
  case $1 in
  --img | -i)
    shift
    img="$1"
    ;;
  --)
    shift
    break
    ;;
  *) exit 1 ;;
  esac
  shift
done

img=${img:-$HOME/Pictures/blank.jpg}
[ -f "$img" ]

# Exec blank window

nohup feh \
  --borderless \
  --full-screen \
  --zoom fill \
  "$img" \
  > /dev/null &
while true; do
  pgrep "feh" > /dev/null 2>&1 && break
  sleep 0.2
done

[ $# -eq 0 ] && exit 0

# Exec input command and bring spawned window to front

nohup "$@" > /dev/null &
target_pid=$!
target_pids="$target_pid"

window_id=''
set -f
IFS='
'
while true; do
  for i in $target_pids; do
    set +f
    unset IFS
    window_id=$(wmctrl -l -p \
      | grep "$i" \
      | cut -d' ' -f1)
    [ -n "$window_id" ] && break
  done
  [ -n "$window_id" ] && break
  sleep 0.2
  target_pids="$target_pid"'
'$(pgrep -P "$target_pid")
done
set +f
unset IFS

xsize.sh --id "$window_id" --move-center
