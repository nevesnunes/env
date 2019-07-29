#!/bin/bash

result=$(lsblk -l | fzf --tac -0 -1)
echo $(echo "$result" | awk "{print $1}")
