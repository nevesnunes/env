#!/bin/sh

set -u

maxdepth=1
if [ "$1" = "--max-depth" ]; then
  shift
  maxdepth=$1
  shift
fi

find . -maxdepth "$maxdepth" -type d | while read -r i; do
  branch=$(git --git-dir="$i/.git" --work-tree="$i" branch 2>&1)
  if ! echo "$branch" | grep -q -i "not a git repo"; then
    git --git-dir="$i/.git" --work-tree="$i" "$@"
  fi
done
