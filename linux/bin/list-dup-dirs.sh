#!/usr/bin/env bash

shopt -s nullglob dotglob

set -- "$PWD"/*/*/

names=()
counts=()
for dirpath do
  name=$( basename "$dirpath" )

  found=false
  for i in "${!names[@]}"; do
    if [[ ${names[i]} == "$name" ]]; then
      found=true
      break
    fi
  done

  if "$found"; then
    counts[i]=$(( counts[i] + 1 ))
  else
    names+=( "$name" )
    counts+=( 1 )
  fi
done

for dirpath do
  name=$( basename "$dirpath" )

  for i in "${!names[@]}"; do
    if [[ ${names[i]} == "$name" ]]; then
      [[ ${counts[i]} -gt 1 ]] && printf '%s\n' "$dirpath"
      break
    fi
  done
done
