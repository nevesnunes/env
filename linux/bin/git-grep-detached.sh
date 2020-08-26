#!/bin/sh

set -eu

git_grep_root=$HOME/code/git_grep_root
mkdir -p "$git_grep_root"

source_dir=$(pwd)
dir=${source_dir#$HOME/}
target_dir=$git_grep_root/$dir
if ! [ -d "$target_dir" ]; then
  mkdir -p "$target_dir"
  cd "$target_dir"
  git init >/dev/null 2>&1
  git config status.showUntrackedFiles no
fi

cd "$target_dir"
git --work-tree=/ add "$source_dir"
git --work-tree=/ commit -m 'sync' >/dev/null 2>&1 || :

input="$*"
entry="$(git grep -n "$*" HEAD \
  | sed 's/^HEAD:/\//' \
  | fzf \
      -0 \
      -1 \
      -q "'$input" \
      --preview '
        filename=$(echo {} | cut -d":" -f1)
        lineno=$(echo {} | cut -d":" -f2)
        query=$(echo {} | cut -d":" -f3-)
        printf "%s\n\n" "$filename:$lineno"
        grep --color=always -C 2 -m 1 -- "$query" "$filename"' \
      --preview-window 'down:8' \
  | cut -d':' -f1-2)"
[ -n "$entry" ] && echo "$entry"
