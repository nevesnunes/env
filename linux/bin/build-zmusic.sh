#!/bin/sh

basename "$PWD" | grep -q ZMusic || cd ~/opt/ZMusic

mkdir -p build
cd build
cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$(pwd)/../build_install" \
  ..
make install
