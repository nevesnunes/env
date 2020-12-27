#!/bin/sh

# References:
# - https://wesley.sh/solved-vmware-workstation-15-fails-to-compile-kernel-modules-with-failed-to-build-vmmon-and-failed-to-build-vmnet/

# This needs to be the actual name of the appropriate branch in mkubecek's GitHub repo for your purposes.
# Use `git branch -a` to list all available branches.
vmware_version=${1:-player-15.1.0}
sources_dir=${2:-/home/$USER/code/dependencies}

(
  mkdir -p "$sources_dir"
  if ! [ -d "$sources_dir/vmware-host-modules" ]; then
    cd "$sources_dir"
    git clone https://github.com/mkubecek/vmware-host-modules
  fi
  cd "$sources_dir/vmware-host-modules"
  git checkout "$vmware_version"
  make
  sudo make install
  # sudo rm /usr/lib/vmware/lib/libz.so.1/libz.so.1
  # sudo ln -s /lib/x86_64-linux-gnu/libz.so.1 /usr/lib/vmware/lib/libz.so.1/libz.so.1
  # systemctl restart vmware && vmware &
)
