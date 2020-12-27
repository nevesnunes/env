#!/usr/bin/env sh

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
