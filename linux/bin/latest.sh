#!/usr/bin/env bash

latest_file=''
latest_timestamp=0
dir="."
if [[ -n $1 ]]; then
  if [[ -d $1 ]]; then
    dir=$1
  else
    exit 1
  fi
fi

state="$HOME/bin/latest.data"
find "$dir" -maxdepth 1 -type f > "$state"
while IFS='' read -r line || [[ -n "$line" ]]; do
    timestamp=$(stat "$line" --printf="%Y\n")
    if [[ $timestamp -gt $latest_timestamp ]]; then
      latest_timestamp=$timestamp
      latest_file=$line
    fi
done < "$state"

if [[ -n $latest_file ]]; then
  echo "$latest_file" 
else
  exit 1
fi

rm "$state"
