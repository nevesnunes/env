#!/usr/bin/env bash

maxdepth=1
if [ "$1" == "--max-depth" ]; then
  shift
  maxdepth=$1
  shift
fi
fun=($@)

list=$(find "$PWD" -maxdepth "$maxdepth" -type d)
while read -r i; do
  branch=$(git --git-dir="$i/.git" --work-tree="$i" branch 2>&1)
  if ! echo "$branch" | grep -q -i "not a git repo"; then
    cd "$i"
    git "${fun[@]}"
  fi
done <<< "$list"
