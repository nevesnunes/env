#!/usr/bin/env bash

fun="$*"
command -v "$1" > /dev/null 2>&1
if [[ $? -eq 1 ]]; then
  echo "bad command."
  exit 1
fi

files=()
for f in "$PWD"/* ; do
  files+=($(readlink -f "$f"))
done

size=${#files[@]}
for (( i=0; i<$size; i++ )); do
  $fun "${files[$i]}"
done
