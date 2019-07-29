#!/usr/bin/env bash

pane_id=$(tmux display-message -p "#{pane_pid}")
child_id=$(pgrep -P "$pane_id" | head -n 1)
if [ -n "$child_id" ]; then
  cmd=$(ps -o command "$child_id" | sed -n 2p)
else
  cmd=$(ps -o command "$pane_id" | sed -n 2p)
fi
printf '%s\n' "$cmd"
