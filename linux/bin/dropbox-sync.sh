#!/usr/bin/env bash

while true; do
	STATUS='dropbox status'
	if [[ ("$STATUS" == "Idle") || ("$STATUS" == "Up to date") ]]; then
    # ...
		exit
  else
    sleep 5
	fi
done
