#!/usr/bin/env bash

process=($(xprop _NET_WM_PID | \
    sed 's/_NET_WM_PID(CARDINAL) = /usr/' | \
    xargs -d'\n' -I{} -n1 -r ps -o command --no-headers {}))
command=$(whereis "${process[0]}" | cut -d' ' -f2)
process[0]=$command
echo "${process[@]}"
