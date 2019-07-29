#!/usr/bin/env bash
pidof xterm
if [[ $? -eq 1 ]]; then
    uxterm -e "tmux attach || tmux new"
else
    uxterm -e "tmux new"
fi
