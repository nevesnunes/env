#!/usr/bin/env sh

set -eu

xmat.py --workarea \
  | awk -F',' '{printf "%s %s", $1 + $3 - 15, $2 + $4 - 40}' \
  | xargs xdotool mousemove
