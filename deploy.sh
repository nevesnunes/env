#!/bin/sh

set -eux

if [ "$(id -u)" -eq 0 ]; then
  echo "WARNING: Running as root, press enter to continue..." >&2
  read -r _

  USER=$(logname)
  [ -d "/home/$USER" ]
fi

role=$1
target=${2:-/home/$USER/}
[ -d "$target" ]
acl=${3:-$USER}

role_dir=$role
if ! [ -d "$role_dir" ] && echo "$role" | grep -qi 'linux'; then
  role_dir=linux
fi
[ -d "$role_dir" ]
if echo "$acl" | grep -qi root; then
    # TODO
    exit 1
else
    rsync -va --usermap=":$acl" --groupmap=":$acl" ./"$role_dir"/ "$target" || true
fi

if [ -x ./tasks/"$role".sh ]; then
  ( cd ./tasks && ./"$role".sh )
fi
