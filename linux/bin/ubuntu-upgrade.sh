#!/usr/bin/env sh

set -eu

sudo apt -y update && \
  sudo apt -y upgrade && \
  sudo apt -y dist-upgrade && \
  sudo apt -y autoremove

sudo apt -y install update-manager-core
sudo do-release-upgrade

# ||
# sudo sed -i 's/xenial/bionic/g' /etc/apt/sources.list /etc/apt/sources.list.d/*
#   sudo apt -y update && \
#   sudo apt -y dist-upgrade
