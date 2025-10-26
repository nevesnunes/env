#!/usr/bin/env sh

set -eu

xmat.py --workarea \
  | awk -F',' '{printf "%s %s", $1 - 15, $2 - 40}' \
  | xargs xdotool mousemove
