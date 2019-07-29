#!/usr/bin/env bash

set -eu

list=$1
[ -f "$list" ] || exit 1
target=$(realpath $2)
[ -d "$target" ] || exit 1

names=()
while read -r i; do
  names+=("$i")
done < "$list"

declare -i name=0
while read -r i; do
  [ -f "$i" ] || continue
  mv "$i" "$target/${names[name]}"
  name+=1
done <<< "$(find "$target" -maxdepth 1)"
