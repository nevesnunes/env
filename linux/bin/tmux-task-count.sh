#!/usr/bin/env bash

file="$XDG_RUNTIME_DIR/bin/task-count.data"
count=$(cat "$file")
if [ -n "$count" ]; then
  echo " $count"
else
  echo ""
fi
