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
    cd "$i"

    git pull
    git fetch --tags

    # Simple skip of bleeding edge tags
    latest_tag=$(git describe --tags "$(git rev-list --tags --max-count=1)")
    if echo "$latest_tag" | grep -q -i -E "alpha|beta|dev|test|unstable"; then
      continue
    fi

    # Ask for build if a new tag was checkout
    current_branch=$(echo "$branch" | grep -i "^\*")
    if ! echo "$current_branch" | grep -q -i "$latest_tag"; then
      git checkout "$latest_tag"
      (
        read -p "$i: Build $latest_tag? (default = NO): " dobuild
        if [[ -n "$dobuild" ]]; then
          ./configure; make; make install
        fi
      ) </dev/tty
    fi
  fi
done <<< "$list"
