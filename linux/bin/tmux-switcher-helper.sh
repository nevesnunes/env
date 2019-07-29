#!/usr/bin/env bash
arr=($@)
echo -n "$(tmux capture-pane -p -t "${arr[0]}:${arr[1]}.${arr[2]}")"
