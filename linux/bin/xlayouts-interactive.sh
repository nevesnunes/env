#!/usr/bin/env sh

input=$(echo "" | dmenu -f -i \
  -p 'Input format: [1-9,]+' \
  -fn 'monospace-14' \
  -nb '#000' -nf '#fff' \
  -sb '#000' -sf '#fff')
xlayouts.sh "Digits" "$input"
