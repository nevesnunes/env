#!/usr/bin/env bash

run_latex() {
  dir="$HOME/Dropbox/ist/tese/dissertacao/documento"
  tmux send-keys -t "$TMUX_PANE" \
    "cd $dir" Enter
  tmux send-keys -t "$TMUX_PANE" \
    "vim --servername LaTeX *.tex Chapters/*" "C-m"
}

run_dev() {
  dir="$HOME/Documents/ist/tese"
  cd "$dir"
  tmux send-keys -t "$TMUX_PANE" "cd $dir" Enter
  python -m SimpleHTTPServer 8888 &

  tmux split-window -v
  tmux select-pane -t 2
  tmux resize-pane -U 10

  tmux new-window
  tmux send-keys -t "$session:{end}" \
      "cd $dir" "C-m"
  tmux send-keys -t "$session:{end}" \
      "vim *.html scripts/*" "C-m"
}

if [ -z "$1" ]; then
  run_latex
fi
while [ "$1" != "" ]; do
  case $1 in
  -d|--dev)
    run_dev
    exit 0
    ;;
  -l|--latex)
    run_latex
    exit 0
  esac
  shift
done
