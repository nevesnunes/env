function t() {
  # We are using bash's string splitting into an array
  emulate -L ksh

  local args="$*"

  # Replace equivalent terms
  if echo "$args" | \
      grep -q -i -E "^[ ]*remove|remove[ ]*$"; then
    args_without_last=$(echo "$args" | awk '{$(NF--)=""; print}')
    args="$args_without_last""delete"
  fi
  args_as_array=($args)
  task "${args_as_array[@]}"

  # Run list to show results of destructive actions
  if echo "$args" | \
      grep -q -i -E "^[ ]*add|^[ ]*delete|^[ ]*edit|^[ ]*done|add[ ]*$|delete[ ]*$|edit[ ]*$|done[ ]*$"; then
      tl
  fi
}

function tl() {
  # We are using bash's string splitting into an array
  emulate -L ksh

  # Extract tasks as lines
  tasks="$(task rc._forcecolor:on list $* 2>&1)"
  due_result="$(echo "$tasks" | head -n 1)"
  if ! echo "$due_result" | grep -q "No matches"; then
    # Remove override warning and task count
    tasks=$(echo "$tasks" | tail -n +2 | head -n -2)
  fi
  OLD_IFS=$IFS
  IFS=$'\n'
  tasks_lines=($tasks)
  IFS=$OLD_IFS

  # Constrain lines to output to screen size
  max_lines=$(( $LINES - 2 ))
  count_lines=${#tasks_lines[@]}
  if [ $count_lines -gt $max_lines ]; then
    count_output_lines=$max_lines
  else
    count_output_lines=$count_lines
  fi

  # Output lines
  clear
  for (( i=0; i<$count_output_lines; i++)); do
    echo "${tasks_lines[$i]}"
  done
  if [ $count_lines -gt $max_lines ]; then
    echo "/!\\ Omitted $(( $count_lines - $max_lines )) tasks."
  fi

  task-count.sh
}
