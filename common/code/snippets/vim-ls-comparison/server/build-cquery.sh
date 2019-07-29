#!/usr/bin/env bash

# https://github.com/cquery-project/cquery/wiki/Building-cquery

set -eu

[ -d cquery ] || git clone --recursive https://github.com/cquery-project/cquery.git
cd cquery
git submodule update --init
mkdir build && cd build
cmake .. \
  -DCMAKE_GENERATOR_PLATFORM=x64 \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=release \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=YES
cmake --build . --config release
cmake --build . --target install
