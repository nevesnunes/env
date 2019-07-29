#!/usr/bin/env bash

dir="$HOME/code/workspace/allkits"
cd "$dir"
tmux send-keys -t "$TMUX_PANE" "cd $dir" Enter
python -m SimpleHTTPServer 8999 &

tmux split-window -v
tmux select-pane -t 2
tmux resize-pane -U 10

tmux new-window
tmux send-keys -t "$session:{end}" \
    "cd $dir" "C-m"
tmux send-keys -t "$session:{end}" \
    "vim *.html app/js/*" "C-m"

tmux new-window
tmux send-keys -t "$session:{end}" \
    "vim $HOME/Dropbox/doc/goals/sweats.md" "C-m"
