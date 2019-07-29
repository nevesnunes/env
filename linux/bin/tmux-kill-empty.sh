#!/usr/bin/env bash

HOME="/home/fn"
PATH="$HOME/bin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"

list1=$(tmux list-sessions)
while read -r i; do
  if ! echo "$i" | grep -q -i "attached"; then
    session=$(echo "$i" | cut -d":" -f1)
    processes=$(tmux list-panes -t "$session" -F \
        "#{pane_pid} #{pane_current_command}")
    
    will_kill_session=true
    while read -r j; do
      if ! echo "$j" | grep -q -i -E "(.*sh$|tmux)"; then
        will_kill_session=false
        break
      fi
    done <<< "$processes"

    if [ "$will_kill_session" = true ]; then
      tmux kill-session -t "$session"
    fi
  fi
done <<< "$list1"
