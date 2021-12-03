#!/bin/sh

set -u

dir_pwd=$PWD

# Search for a parent directory with tags
dir=$dir_pwd
while [ "$dir" != "$HOME" ] && [ "$dir" != "/"  ]; do
  cd "$dir"
  if [ -f "$dir/tags" ]; then
    ctags -R .
    if [ "$?" -eq 1 ]; then
      ctags -f ~/tmp/tags -R .
    fi
    exit 0
  fi
  dir=$(dirname "$dir")
done

# No tags found: Create in current directory
cd "$dir_pwd"
ctags -R .
if [ "$?" -eq 1 ]; then
  ctags -f ~/tmp/tags -R .
fi
