#!/bin/bash

source bin-utils.sh

due_today=$(task list due:today)
due_today_result="$(echo "$due_today" | sed -n 1p)"
echo $due_today_result
if [[ -z $(match "$due_today_result" "No matches") ]]; then
  tasks=$(echo "$due_today" | tail -n 3)
  notify-send "Tasks for today:" "$tasks"
fi
