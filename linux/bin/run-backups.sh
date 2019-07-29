#!/usr/bin/env bash

function trello() {
  target_dir="$HOME/opt/trello-backup/"
  cd "$target_dir"
  tar -zcvf "$HOME/backups/trello-$date_archive.tar.gz" \
      -C "$target_dir" ./*.json
}

HOME="/home/fn"
PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"
TERM=screen-256color
export DISPLAY=:0.0

# Setup
mkdir -p "$HOME/backups"
date_archive=$(date +"%Y-%m-%d")

# Backup

# Rotate
find "$HOME/backups/" -mtime +30 -exec rm -rv {} \;
