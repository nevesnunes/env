#!/usr/bin/env bash

tmp_dir="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
mkdir -p "$tmp_dir"
chmod 700 "$tmp_dir"
file="$tmp_dir/task-count.data"
count=$(cat "$file")
if [ -n "$count" ]; then
  echo " $count"
else
  echo ""
fi
