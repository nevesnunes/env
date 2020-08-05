#!/usr/bin/env bash

# Usage:
# pistoleiro.sh PORT -iwad doom.wad  -file FILE [...] -warp '4 1'
# pistoleiro.sh PORT -iwad doom2.wad -file FILE [...] -warp 16

set -e

function cleanup() {
  killall -9 "$port_name" &> /dev/null || true
  clear
}
trap cleanup EXIT
trap '>&2 echo Error at line "$LINENO": $(sed -n "${LINENO}"p "$0")' ERR

next_warp() {
  warp=$1
  if [ "$(echo -n "$warp" | wc -c)" -gt 2 ]; then
    episode=$(echo -n "$warp" | cut -d' ' -f1)
    map=$(echo -n "$warp" | cut -d' ' -f2)
    map=$((map + 1))
    if [ "$map" -gt 9 ]; then
      episode=$((episode + 1))
      map=1
    fi
    echo -n "$episode $map"
  else
    echo -n $((warp + 1))
  fi
}

port=$1
port_name=${port//.sh/}
command -v "$port" &> /dev/null
shift

args=()
if echo "$*" | grep -qi "doom.wad"; then
  warp="1 1"
else
  warp=1
fi
no_warp=true
while [ "$1" != "" ]; do
  case $1 in
  -file)
    args+=("$1")
    shift
    file=$1
    [ -f "$file" ]
    args+=("$1")
    ;;
  -iwad)
    args+=("$1")
    shift
    iwad=$1
    [ -f "$iwad" ]
    args+=("$1")
    ;;
  -warp)
    args+=("$1")
    shift
    warp=$1
    no_warp=false
    ;;
  *)
    args+=("$1")
    ;;
  esac
  shift
done
if [[ $no_warp == true ]]; then
  args+=('-warp')
fi

if [ -z "$file" ]; then
  file="$iwad"
fi
path="$(realpath "$(dirname "$file")")"
warp_file="$path/$(echo "$file" | sed 's/\(.*\/\)\?\([^.]*\).*/\2/').warp"
touch "$warp_file"
if [ -s "$warp_file" ]; then
  warp=$(head -n 1 "$warp_file")
fi

# Adjust window resolution,
# using 4/3 ratio (e.g. 320/240),
# to match vertically stretched 8/5 ratio (e.g. 320/200)
# as displayed by VGA cards in mode 13h on CRT monitors.
#
# On multi-monitor setups, use geometry of monitor in which the largest area of active window resides.
#
# References:
# - https://doomwiki.org/wiki/Aspect_ratio
#
# Alternatives:
# - https://superuser.com/questions/196532/how-do-i-find-out-my-screen-resolution-from-a-shell-script
# - https://askubuntu.com/questions/584688/how-can-i-get-the-monitor-resolution-using-the-command-line
# h=$(wmctrl -d \
#   | grep '\*' \
#   | sed 's/.*[0-9]\+x[0-9]\+.*[0-9]\+x\([0-9]\+\).*/\1/')
h=$(xgeo.py 2>/dev/null \
  | sed 's/.*[0-9]\+x\([0-9]\+\).*/\1/')
if [ "$h" -lt 800 ]; then
  target_w=896
  target_h=672
else
  target_w=1152
  target_h=864
fi
if command -v wmctrl &> /dev/null; then
  if echo "$port" | grep -qi gzdoom; then
    sed -i '
      s/^\(win_w=\)[0-9]*/\1'${target_w}'/;
      s/^\(win_h=\)[0-9]*/\1'${target_h}'/;
      ' ~/.config/gzdoom/gzdoom.ini
  elif echo "$port" | grep -qi prboom; then
    sed -i '
      s/^\(screen_resolution[[:space:]]*\)"[0-9]*x[0-9]*"/\1"'${target_w}x${target_h}'"/
      ' ~/.prboom-plus/prboom-plus.cfg
  elif echo "$port" | grep -qi crispy-doom; then
    sed -i '
      s/^\(window_width[[:space:]]*\)[0-9]*/\1'${target_w}'/;
      s/^\(window_height[[:space:]]*\)[0-9]*/\1'${target_h}'/;
      ' ~/.local/share/crispy-doom/crispy-doom.cfg
  elif echo "$port" | grep -qi chocolate-doom; then
    sed -i '
      s/^\(screen_width[[:space:]]*\)[0-9]*/\1'${target_w}'/;
      s/^\(screen_height[[:space:]]*\)[0-9]*/\1'${target_h}'/;
      ' ~/.chocolate-doom/chocolate-doom.cfg
  fi
fi

while true; do
  cleanup

  echo "$warp" > "$warp_file"

  command -v xdotool &> /dev/null \
    && xdotool getactivewindow windowminimize

  # shellcheck disable=SC2086
  env SDL_AUDIODRIVER=alsa PULSE_LATENCY_MSEC=150 \
    "$port" "${args[@]}" $warp &> /dev/null &

  warp=$(next_warp "$warp")
  if echo "$warp" | grep -q '^7\|12\|21$'; then
    echo '/!\ This map has a text screen.'
  fi
  read -r -n1 -p "Press any key to pistol-start map $warp." _

  # Process was terminated outside this script
  pgrep "$port_name" &> /dev/null || exit
done
