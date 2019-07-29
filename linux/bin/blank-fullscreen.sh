#!/usr/bin/env sh

set -x

nohup feh --borderless --full-screen --zoom fill ~/Pictures/blank.jpg >/dev/null &
[ -n "$1" ] || exit 1
while true; do
  pgrep "feh" >/dev/null 2>&1 && break
  sleep 0.2
done

nohup "$@" >/dev/null &
target_pid=$!
target_pids="$target_pid"

window_id=''
set -f; IFS='
'
while true; do
  for i in $target_pids; do
    set +f; unset IFS
    window_id=$(wmctrl -l -p | \
      grep "$i" | \
      cut -d' ' -f1)
    [ -n "$window_id" ] && break
  done
  [ -n "$window_id" ] && break
  sleep 0.2
  target_pids="$target_pid"'
'$(pgrep -P "$target_pid")
done
set +f; unset IFS

xsize.sh --id "$window_id" --move-center;
