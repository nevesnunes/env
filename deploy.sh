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
elif echo "$role" | grep -qi 'linux-dev'; then
    rsync -va --relative --usermap=":$acl" --groupmap=":$acl" \
      ./common/./code/cheats \
      ./"$role_dir"/./.bash* \
      ./"$role_dir"/./.dircolors* \
      ./"$role_dir"/./.less* \
      ./"$role_dir"/./.infokey \
      ./"$role_dir"/./.inputrc \
      ./"$role_dir"/./.lscolors \
      ./"$role_dir"/./.profile* \
      ./"$role_dir"/./.shrc \
      ./"$role_dir"/./.vim \
      ./"$role_dir"/./.vimrc \
      ./"$role_dir"/./.Xresources* \
      ./"$role_dir"/./.zshrc \
      ./"$role_dir"/./.local/share/functions \
      ./"$role_dir"/./.local/share/terminfo \
      ./"$role_dir"/./.local/share/Xresources \
      ./"$role_dir"/./bin \
      "$target" || true
else
    rsync -va --usermap=":$acl" --groupmap=":$acl" ./"$role_dir"/ "$target" || true
fi

if [ -x ./tasks/"$role".sh ]; then
  ( cd ./tasks && ./"$role".sh )
fi
