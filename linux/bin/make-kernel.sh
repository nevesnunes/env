#!/usr/bin/env sh

# Bootstrap from existing config (e.g. /boot/config*):
# - make oldconfig
# Bootstrap from currently loaded modules:
# - make localmodconfig
# References:
# - https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/README.rst#configuring-the-kernel

set -eux

[ -f .config ]

jobs_arg="-j"
if command -v nproc >/dev/null 2>&1; then
  jobs_arg="-j$(nproc --ignore=2)"
fi
make "$jobs_arg" oldconfig && \
  make "$jobs_arg" bzImage && \
  make "$jobs_arg" modules && \
  sudo make modules_install && \
  sudo make install 
