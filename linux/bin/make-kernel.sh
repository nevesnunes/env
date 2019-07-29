#!/usr/bin/env sh

set -eux

[ -f .config ]
make oldconfig && \
  make bzImage && \
  make modules && \
  sudo make modules_install && \
  sudo make install 
