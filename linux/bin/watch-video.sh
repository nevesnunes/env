#!/usr/bin/env bash

wait_hours=$1

xset s off -dpms

clear
if [[ -n $wait_hours ]]; then
  wait_seconds=$((60*60*$wait_hours))
  wait_noun="hours"
  if [[ $wait_hours -eq 1 ]]; then
    wait_noun="hour"
  fi
  echo "Waiting $wait_hours $wait_noun to resume energy saving..."
  sleep $wait_seconds
else
  echo "Press any key to resume energy saving..."
  read -r -n 1
fi

xset s on +dpms 
