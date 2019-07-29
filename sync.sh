#!/bin/sh

set -eux

for script in backup.sh deploy.sh; do
  ./"$script" common
  if uname -o | grep -i linux; then
    ./"$script" linux
    ./"$script" linux-root / root
  elif uname -o | grep -i msys; then
    ./"$script" windows
  else
    exit 1
  fi
done
