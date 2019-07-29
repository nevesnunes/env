#!/usr/bin/env bash

current_window_id=$(tmux display-message -p '#{window_index}')
current_pane_id=$(tmux display-message -p '#{pane_index}')

panes=$(tmux list-panes -s -F \
    '#{window_index} #{pane_index} #{pane_current_path}')
result=()
while read -r pane; do
  window_id=$(echo "$pane" | cut -d' ' -f1)
  pane_id=$(echo "$pane" | cut -d' ' -f2)
  if [ "$window_id" -eq "$current_window_id" ] && \
      [ "$pane_id" -ne "$current_pane_id" ]; then
    result+=("$(echo "$pane" | cut -d' ' -f3-)")
  fi
done <<< "$panes"

target_cd=""
if [ ${#result[@]} -gt 1 ]; then
  choose_cd=""
  for var in "${result[@]}"; do
    choose_cd+="$var\n"
  done
  target_cd=$(echo -e "$choose_cd" | fzf)
else
  target_cd=${result[0]}
fi

echo "$target_cd"
