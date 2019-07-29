#!/usr/bin/env bash

function make_permutations_from_arrays() {
  declare -a items=("${!1}")
  declare -a out=("${!2}")
  local i
	if [[ ${#items[@]} -lt 1 ]]; then
		results+=("${out[*]}")
    return
  fi
  for (( i=0; i<${#items[@]}; i++ )) ; do
    local A=("${items[@]:0:i}" "${items[@]:i+1}")
    local B=("${out[@]}" "${items[@]:i:1}")
    make_permutations_from_arrays A[@] B[@]
  done
}

args=($@)
args_empty=()
results=()
make_permutations_from_arrays args[@] args_empty[@] 
for (( i=0; i<${#results[@]}; i++ )) ; do
  echo ${results[i]}
done
