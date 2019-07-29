#!/bin/bash

if [ ! -f "$1" ]; then
  echo "Bad file."
  exit 1
fi

description=""
descriptions=()
action=""
actions=()
while read -r line; do
  # ignore blank lines
  if [[ "$line" =~ ^[[:space:]]*$ ]]; then
    continue
  fi

  # ignore comments between split action
  if [[ "$line" =~ ^# ]] && [[ -n "$action" ]]; then
    continue
  fi

  # remove both leading and trailing spaces
  line="$(echo -e "$line" | sed \
      -e 's/^[[:space:]]*//' \
      -e 's/[[:space:]]*$//')"

  # line is a description
  if [[ "$line" =~ ^# ]]; then
    line="$(echo -e "$line" | sed \
        -e 's/#*[[:space:]]*//')"
    # if we read a description in the previous line, append this to it
    if [[ -n "$description" ]]; then
      line=" $line"
    fi
    description+="$line"
  else
    # line is the start of an action
    if [[ "$line" =~ \\$ ]]; then
      line="$(echo -e "$line" | sed \
          -e 's/[[:space:]]*\\//')"
      action+="$line "
    # line is the end of an action
    else
      descriptions+=("$description")
      description=""
      action+="$line"
      actions+=("$action")
      action=""
    fi
  fi
done < "$1"

# make selectable options from available actions
options=""
size=${#descriptions[@]}
options+=${descriptions[0]}
for (( i=1; i<$size; i++ )); do
  options+="\n${descriptions[$i]}"
done

# choose an action
result=$(echo -e "$options" | fzf)

# run the choosen action
size=${#descriptions[@]}
for (( i=0; i<=$size; i++ )); do
  if [[ $result == "${descriptions[$i]}" ]] ; then
    echo "${actions[$i]}"
    exit 0
  fi
done
