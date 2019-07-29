#!/usr/bin/env bash

args="$*"

function config-to-lists() {
  description=""
  action=""
  while read -r line; do
    # ignore blank lines
    if [[ "$line" =~ ^[[:space:]]*$ ]]; then
      continue
    fi

    # remove non-printable characters
    line="$(echo -e "$line" | tr \
        -dc '[:alnum:][:space:][:punct:]')"

    # remove both leading and trailing spaces
    line="$(echo -e "$line" | sed \
        -e 's/^[[:space:]]*//' \
        -e 's/[[:space:]]*$//')"

    # line is a description
    if [[ "$line" =~ ^# ]]; then
      if [[ -n "$action" ]]; then
        description+="$line"
        descriptions+=("$description")
        description=""
        actions+=("$action")
        action=""
      else
        line="$(echo -e "$line" | sed \
            -e 's/#*[[:space:]]*//')"
        # if we read a description in the previous line, append this to it
        if [[ -n "$description" ]]; then
          line=" $line"
        fi
        description+="$line"
      fi
    else
      # line is part of an action
      action+="$line "
    fi
  done < "$1"
}

typed_descriptions=()
typed_actions=()

function parse-typed() {
  local descriptions=()
  local actions=()
  config-to-lists "$1"
  typed_descriptions+=("${descriptions[@]}")
  typed_actions+=("${actions[@]}")
}
parse-typed ~/kb/apache-sec.md

if [[ -n "$args" ]]; then
  args="$args "
fi

result=$(printf '%s\n' "${typed_descriptions[@]}" \
    | fzf -0 -1 -q "'$args" --preview 'echo {} | fold -w $((COLUMNS-4)) | head -n 4' --preview-window down:4)
if [[ $result == "" ]]; then
  exit 1
else
  size=${#typed_descriptions[@]}
  for (( i=0; i<=$size; i++ )); do
    if [[ $result == "${typed_descriptions[$i]}" ]] ; then
      txt="${typed_actions[$i]}"

      # Edit placeholders if they exist
      if echo "$txt" | grep -q -i '%%%'; then
        tmp_file=$(mktemp)
        trap 'rm -f "$tmp_file"' EXIT

        echo -n "$txt" > "$tmp_file"
        gvim -v -c "execute '/%%%' | call feedkeys('nvE', 'n')" "$tmp_file"
        txt=$(cat "$tmp_file")
      fi
      echo "$txt"
    fi
  done
fi
