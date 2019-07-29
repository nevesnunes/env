#!/bin/bash

case "$1" in
resume|thaw)
    /opt/notify-tasks.sh
    ;;
esac
