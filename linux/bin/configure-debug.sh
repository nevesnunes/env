#!/bin/sh

# Builds app with debug symbols.
# 
# Reference:
# https://stackoverflow.com/a/4680578/8020917

# Running under gdb:
# libtool --mode=execute gdb --args ...

set -eu

if [ -f Makefile ]; then
  make distclean || true
fi

mkdir -p debug
(
  cd debug 

  # To ensure breakpoints are always set
  # in the corresponding source code line and
  # in a single location,
  # compile with `-fno-inline-functions` or
  # disable optimizations with `-O0`.
  gdb_flags='-ggdb3 -O0'
  ../configure \
    --prefix=/debug \
    CFLAGS="$gdb_flags" \
    CPPFLAGS="-DDEBUG $gdb_flags" \
    CXXFLAGS="$gdb_flags"

  make
)

# mkdir -p release
# (
#   cd release
# 
#   ../configure \
#     CPPFLAGS=-DNDEBUG
# 
#   make
# )
