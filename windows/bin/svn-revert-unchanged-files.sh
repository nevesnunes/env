#!/usr/bin/env bash

while read -r f; do
  hasChanges="$(diff -Naurw "$f" <(echo -n "$(svn cat -r HEAD $f)"))"
  [ -z "$hasChanges" ] && svn revert "$f"
done <<< "$(find . -type f)"
