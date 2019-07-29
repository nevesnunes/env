#!/usr/bin/env bash

block='▬'
max_length=10

lines=''
for ((i=0; i<20; i++)); do
  rand=$(( $RANDOM % 100 ))
  num_blocks=$(( $(( rand / max_length )) + 1 ))
  blocks=$block
  for ((j=1; j<$num_blocks; j++)); do
    blocks+=$block
  done
  num_spaces=$((max_length - num_blocks))
  spaces=''
  for ((k=0; k<$num_spaces; k++)); do
    spaces+=' '
  done
  lines+="$spaces$blocks $rand"
  lines+="\n"
done

echo -e -n "$lines" | fzf
