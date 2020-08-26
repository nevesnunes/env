#!/bin/sh

# Allows usage of `git grep` for directories outside of a sub tree, creating a git repo with that directory as work tree

# TODO:
# - Synonym expansion
#   - fzf -q: ^core go$ | rb$ | py$

set -eu

git_grep_root=$HOME/code/git_grep_root
mkdir -p "$git_grep_root"

# Check if current dir needs processing
source_dir=$PWD
target_dir=$git_grep_root/${source_dir#$HOME/}
parent_dir=$source_dir
is_git_repo=
is_processed=
if git -C "$parent_dir" rev-parse 2>/dev/null; then
  is_git_repo=1
  target_dir=$source_dir
else
  while [ "$parent_dir" != "/" ]; do
    if [ -d "$git_grep_root/$parent_dir" ]; then
      is_processed=1
      target_dir=$git_grep_root/$parent_dir
      break
    fi
    parent_dir=$(dirname "$parent_dir")
  done
fi

# Don't create repo if child dir is part of subtree or repo for parent dir is available
if ! [ -d "$target_dir" ] && [ -z "$is_git_repo" ] && [ -z "$is_processed" ]; then
  mkdir -p "$target_dir"
  cd "$target_dir"
  git init >/dev/null 2>&1
  git config status.showUntrackedFiles no
fi

cd "$target_dir"
if [ -z "$is_git_repo" ]; then
  git --work-tree=/ add "$source_dir"
  git --work-tree=/ commit -m 'sync' >/dev/null 2>&1 || :
fi

source_dir_escaped=
if [ -n "$is_git_repo" ]; then
  # Subtree matches are relative to repo, thus convert them to absolute paths.
  # Reference: [regex \- special characters in sed \- Stack Overflow](https://stackoverflow.com/a/13500157/8020917)
  source_dir_escaped=$(echo "$source_dir" | sed 's/[\^\[\\\/\.\*\$]/\\&/g')
fi
input="$*"
entry="$(git grep -n "$*" HEAD \
  | sed "s/^HEAD:/$source_dir_escaped\//" \
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
echo "$entry"
