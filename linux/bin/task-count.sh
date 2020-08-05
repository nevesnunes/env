#!/bin/sh

tmp_dir="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
mkdir -p "$tmp_dir"
chmod 700 "$tmp_dir"
file="$tmp_dir/task-count.data"
touch "$file"

inc() {
  due_result="$(echo "$1" | head -n 1)"
  if ! echo "$due_result" | grep -q -i "No matches"; then
    echo "$1" | tail -n +4 | head -n -2 | wc -l
  else
    echo 0
  fi
}

count_week=$(inc "$(task list \
    due.after:today-1w and due.before:today 2>&1)")
count_today=$(inc "$(task list \
    due:today 2>&1)")
count_tomorrow=$(inc "$(task list \
    due:tomorrow 2>&1)")

bold="#[fg=default,bold]"
reset="#[fg=default,nobold]"

needSeparator=false
description=""
if [ $((count_week + count_today + count_tomorrow)) -gt 0 ]; then
  description="${description}["
  if [ "$count_week" -gt 0 ]; then
    needSeparator=true
    description="${description}-1w:$bold$count_week$reset"
  fi
  if [ "$count_today" -gt 0 ]; then
    if [ "$needSeparator" = true ]; then
      description="${description} "
    fi
    needSeparator=true
    description="${description}0d:$bold$count_today$reset"
  fi
  if [ "$count_tomorrow" -gt 0 ]; then
    if [ "$needSeparator" = true ]; then
      description="${description} "
    fi
    needSeparator=true
    description="${description}+1d:$bold$count_tomorrow$reset"
  fi
  description="${description}]"
fi
echo "$description" > "$file"
