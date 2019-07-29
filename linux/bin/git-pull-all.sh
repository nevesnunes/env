#!/usr/bin/env bash

if [ -n "$1" ]; then
  dir="$1"
else
  dir="$PWD"
fi

list=$(find "$dir" -maxdepth 2 -type d)
while read -r i; do
  branch=$(git --git-dir="$i/.git" --work-tree="$i" branch 2>&1)
  if ! echo "$branch" | grep -q -i "not a git repo"; then
    is_master=$(echo "$branch" | grep -i "^\* master")
    if [ -z "$is_master" ]; then
      echo "[WARN] Repo is not on master: $i"
    fi

    git --git-dir="$i/.git" --work-tree="$i" pull
  fi
done <<< "$list"
