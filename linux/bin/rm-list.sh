#!/usr/bin/env bash

set -eu

list=$1
[ -f "$list" ] || exit 1
target_dir=$(realpath "$2")
[ -d "$target_dir" ] || exit 1

while read -r i; do
  [ -z "$i" ] && continue
  target="${target_dir:?}/$i"
  ! [ -d "$target" ] && ! [ -f "$target" ] && continue
  target=$(realpath "$target")
  [ "$target" = "$target_dir" ] && continue
  echo "$target"
  rm -rf "$target"
done < "$list"
