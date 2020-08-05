#!/bin/sh

set -eu

build-zmusic.sh
ZMUSIC_LIBRARIES=$HOME/opt/ZMusic/build_install/lib64
ZMUSIC_INCLUDE_DIR=$HOME/opt/ZMusic/build_install/include

basename "$PWD" | grep -q zdoom || cd ~/opt/gzdoom

git config --local remote.origin.fetch \
  | grep -q 'refs/tags' \
  || git config --local --add remote.origin.fetch +refs/tags/*:refs/tags/*
git pull

mkdir -p build/
cd build/
a='' && [ "$(uname -m)" = x86_64 ] && a=64
c="$(lscpu -p | grep -v '#' | sort -u -t , -k 2,4 | wc -l)" ; [ "$c" -eq 0 ] && c=1
rm -f output_sdl/liboutput_sdl.so
f='-UFMOD_LIBRARY -UFMOD_INCLUDE_DIR' && [ -d fmodapi44464linux ] &&
f="-DFMOD_LIBRARY=fmodapi44464linux/api/lib/libfmodex${a}-4.44.64.so \
-DFMOD_INCLUDE_DIR=fmodapi44464linux/api/inc"
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$ZMUSIC_LIBRARIES" \
  -DZMUSIC_INCLUDE_DIR="$ZMUSIC_INCLUDE_DIR" \
  $f &&
make -j$c
