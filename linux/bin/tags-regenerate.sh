#!/usr/bin/env bash

dir_pwd=$PWD

# Search for a parent directory with tags
dir=$dir_pwd
while [[ "$dir" != "$HOME" ]] && [[ "$dir" != "/"  ]]; do
  cd "$dir"
  if [[ -f "$dir/tags" ]]; then
    ctags -R . || ctags -f ~/tmp/tags -R .
    exit 0
  fi
  dir=$(dirname "$dir")
done

# No tags found: Create in current directory
cd "$dir_pwd"
ctags -R . || ctags -f ~/tmp/tags -R .
