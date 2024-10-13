#!/bin/sh

# Reference: https://gist.github.com/dmytro/3984680

tmux attach-session -t 0

first=
for i in "$@"; do
  if [ -z "$first" ]; then
    first=$i
    tmux send-keys "ssh $i" Enter
  else
    tmux split-window "ssh $i"
  fi
  tmux select-layout tiled
done
tmux select-pane -t 0
tmux set-window-option synchronize-panes on
