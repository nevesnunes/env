#!/bin/sh

os() {
  if [ -f /etc/os-release ]; then
    # freedesktop.org and systemd
    . /etc/os-release
    OS=$NAME
  elif type lsb_release &>/dev/null; then
    # linuxbase.org
    OS=$(lsb_release -si)
  elif [ -f /etc/lsb-release ]; then
    # For some versions of Debian/Ubuntu without lsb_release command
    . /etc/lsb-release
    OS=$DISTRIB_ID
  elif [ -f /etc/debian_version ]; then
    # Older Debian/Ubuntu/etc.
    OS=Debian
  else
    # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
    OS=$(uname -s)
  fi
  echo "$OS"
}

yi() {
  if os | grep -qi 'centos\|fedora'; then
    sudo /usr/bin/dnf install -y "$@"
  else
    sudo /usr/bin/apt install -y "$@"
  fi
}

yp() {
  if os | grep -qi 'centos\|fedora'; then
    sudo /usr/bin/dnf -C provides "$@"
  else
    sudo /usr/bin/dpkg -S "$@"
  fi
}

yr() {
  if os | grep -qi 'centos\|fedora'; then
    sudo /usr/bin/dnf remove "$@"
  else
    sudo /usr/bin/apt purge "$@"
  fi
}

ys() {
  if os | grep -qi 'centos\|fedora'; then
    sudo /usr/bin/dnf -C search "$@"
  else
    sudo /usr/bin/apt search "$@"
  fi
}

yu() {
  if os | grep -qi 'centos\|fedora'; then
    sudo /usr/bin/dnf upgrade -y "$@"
  else
    sudo /usr/bin/apt update -y && sudo /usr/bin/apt upgrade -y "$@"
  fi
}
