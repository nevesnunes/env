#!/bin/sh

set -u

if [ -n "$1" ]; then
  dir="$1"
else
  dir="$PWD"
fi

find "$dir" -maxdepth 2 -type d | while read -r i; do
  branch=$(git --git-dir="$i/.git" --work-tree="$i" branch 2>&1)
  if ! echo "$branch" | grep -q -i "not a git repo"; then
    cd "$i"

    git pull
    git fetch --tags

    # Skip bleeding edge tags
    latest_tag=$(git rev-list --tags --max-count=1 | xargs -i git describe --tags {})
    if echo "$latest_tag" | grep -q -i -E "alpha|beta|dev|test|unstable"; then
      continue
    fi

    # Ask for build if a new tag was checkout
    current_branch=$(echo "$branch" | grep -i "^\*")
    if ! echo "$current_branch" | grep -q -i "$latest_tag"; then
      git checkout "$latest_tag"
      (
        printf '%s' "$i: Build $latest_tag? (default = NO): "
        read -r should_build
        if [ -n "$should_build" ]; then
          ./configure
          make
          make install
        fi
      ) < /dev/tty
    fi
  fi
done
