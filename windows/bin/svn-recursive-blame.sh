#!/usr/bin/env bash

# Usage:
# $0 'http://HOST/trunk/PROJECT/src/main/java/FOO.java@REVISION' 'PATTERN'

set -eu

seen_revisions=""
function blame {
  local url=$1
  local pattern=$2
  local revision=${url##*@}
  local url=${url%@*}

  local pending_revisions=()
  local matched_lines=""
  while read -r i; do
    revision=$(echo "$i" | awk '{ print $1 }')
    [ -z "$revision" ] && return

    matched_lines+=$i$'\n'

    if ! echo "$seen_revisions" | grep -q "$revision"; then
      pending_revisions+=("$revision")
      seen_revisions+="$revision "
    fi
  done <<< "$(svn blame "$url@$revision" 2>/dev/null | grep -i "$pattern" || true)"

  for i in "${pending_revisions[@]}"; do
    svn log -r "$i"
  done

  echo -e "$(tput bold)$(tput setaf 1)$matched_lines$(tput sgr0)"

  for i in "${pending_revisions[@]}"; do
    blame "$url@$(($i - 1))" "$pattern"
  done
}

blame "$1" "$2"
