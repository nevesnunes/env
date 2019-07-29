#!/usr/bin/env sh

# Create a discardable git repository 
# from a given directory, used by a given script.
# When that script finishes, the repository is removed.

set -e

repo=$(mktemp -d)
[ -d "$repo" ]
trap 'rm -rf "$repo"' EXIT QUIT INT TERM

dir=$(realpath "$1")
script=$2
[ -d "$dir" ] && [ -n "$script" ]
[ -f "$script" ] && script=$(realpath "$script")

cd "$repo"
git init >/dev/null 2>&1
cp -r "$dir/." .
git add -A >/dev/null 2>&1
git commit -m "Automatic commit for $repo" >/dev/null 2>&1

if [ -f "$script" ]; then
  bash -c "$script"
else
  eval "$script"
fi
