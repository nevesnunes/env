#!/usr/bin/env bash

PIPE=/tmp/my-script.out
mkfifo $PIPE

systemd-cat < $PIPE &
exec 3>$PIPE

echo message > $PIPE
echo other message >&3

# Closing file descriptor 3 closes the fifo
exec 3>&-
