#!/usr/bin/env bash

set -eu

cmd=$(echo "$*" | sed 's/p=[0-9]*\?/p=$i/')
for ((i=1;i<100;i++)); do 
  eval "$cmd" > ~/repos-$i.html 
  sleep $((RANDOM % 5));
done

find . -maxdepth 1 -iname 'repos-*' | xargs -I{} -d'\n' -n1 github-repos.py {} >> ~/repos.sh
