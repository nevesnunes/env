#!/bin/sh

set -eux

ARCH=${1:-x86_64}
DEPS=${2:-$HOME/opt}
BUILD=$(gcc -dumpmachine)
HOST=$ARCH-linux-musl
CROSS=$ARCH-unknown-linux-musl
PREFIX=$HOME/share/toolchains/$HOST-cross

AR=$PREFIX/bin/$HOST-ar
CC="$PREFIX/bin/$HOST-gcc -static --static"
CXX="$PREFIX/bin/$HOST-g++ -static --static"
#LDFLAGS="-s -static --static"

cd "$DEPS"/gmp-*
test -f ./Makefile && make distclean
./configure --build="$BUILD" --host="$HOST" --prefix="$PREFIX" --disable-shared --enable-static CC="$CC" CXX="$CXX"
make -j4 CC="$CC" CXX="$CXX" CROSS="$CROSS"
make install

cd "$DEPS"/mpfr-*
test -f ./Makefile && make distclean
./configure --build="$BUILD" --host="$HOST" --prefix="$PREFIX" --disable-shared --enable-static --with-gmp="$PREFIX" CC="$CC" CXX="$CXX"
make -j4 CC="$CC" CXX="$CXX" CROSS="$CROSS"
make install

cd "$(find "$DEPS" -maxdepth 1 -iregex '.*gdb-[0-9].*' | tail -n1)"
export PATH="$PATH:$PREFIX/bin"
test -f ./Makefile && make distclean
./configure --build="$BUILD" --host="$HOST" --prefix="$PREFIX" --disable-sim --disable-inprocess-agent --disable-interprocess-agent --enable-static --with-static-standard-libraries --with-pic --with-gmp="$PREFIX" --with-mpfr="$PREFIX" AR="$AR" CC="$CC" CXX="$CXX"
make all-gdb -j4 AR="$AR" CC="$CC" CXX="$CXX" CROSS="$CROSS"
