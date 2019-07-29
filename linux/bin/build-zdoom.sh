#!/bin/sh

set -eu

a='' && [ "$(uname -m)" = x86_64 ] && a=64
c="$(lscpu -p | grep -v '#' | sort -u -t , -k 2,4 | wc -l)" ; [ "$c" -eq 0 ] && c=1
rm -f output_sdl/liboutput_sdl.so
f='-UFMOD_LIBRARY -UFMOD_INCLUDE_DIR' && [ -d fmodapi44464linux ] &&
f="-DFMOD_LIBRARY=fmodapi44464linux/api/lib/libfmodex${a}-4.44.64.so \
-DFMOD_INCLUDE_DIR=fmodapi44464linux/api/inc"
cmake .. -DCMAKE_BUILD_TYPE=Release $f &&
make -j$c
