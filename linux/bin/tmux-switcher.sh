#!/usr/bin/env bash

list1=$(tmux list-panes -a -F \
    "#{pane_pid} #{session_id} #{window_index} #{pane_index} #T:#{pane_current_path}")
panes=()
while read -r i; do
  pane_id=$(echo "$i" | awk '{print $1}')
  child_id=$(pgrep -P "$pane_id" | head -n 1)
  if [ -n "$child_id" ]; then
    cmd=$(ps -o command "$child_id" | sed -n 2p)
  else
    cmd=$(ps -o command "$pane_id" | sed -n 2p)
  fi
  session=$(echo "$i" | awk '{print $2}')
  session=${session:1}
  panes+=("$(echo "$i" | \
      awk -v cmd="$cmd" -v session="$session" '{print session" "$3" "$4" "cmd" "$5}')")
done <<< "$list1"

previewer=(--preview "tmux-switcher-helper.sh {}" \
      --preview-window down:10 --color border:7)
result=$(printf '%s\n' "${panes[@]}" | fzf -0 -1 "${previewer[@]}")
session=$(echo -n "$result" | cut -d' ' -f1)
window=$(echo -n "$result" | cut -d' ' -f2)
pane=$(echo -n "$result" | cut -d' ' -f3)
tmux switch -t "$session"
tmux select-window -t "$window"
tmux select-pane -t "$pane"
