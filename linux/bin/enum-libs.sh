#!/usr/bin/env bash

target=$(realpath "$1")

function process() {
  local to_process=()
  for i in "${to_see[@]}"; do
    if ! printf '%s\n' "${seen[@]}" | \
        grep -qi "$i"; then
      to_process+=("$i")
    fi
  done

  to_see=()
  for i in "${to_process[@]}"; do
    local lib_to_process="/lib64/$i"
    if [ ! -f "$lib_to_process" ]; then
      lib_to_process="/lib/$i"
    fi
    to_see+=("$(readelf -d "$lib_to_process" | \
           grep 'NEEDED' | \
           sed 's/.*\[\(.*\)\].*/\1/')")
    seen+=("$i")
  done
}

seen=()
to_see=()
while read -r i; do
  to_see+=("$i")
done <<< "$(readelf -d "$target" | \
       grep 'NEEDED' | \
       sed 's/.*\[\(.*\)\].*/\1/')"
while [ "${#to_see[@]}" -gt 0 ]; do
  process
done

printf '%s\n' "${seen[@]}"
