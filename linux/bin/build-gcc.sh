#!/bin/sh

set -eu

TARGET=$1
PREFIX=$2
GCC_DIR=$3

cd "$GCC_DIR"
./contrib/download_prerequisites

cd "$GCC_DIR"/gmp-*/
./configure --disable-shared --enable-static --prefix="$PREFIX"
make distclean && make && make check && make install

cd "$GCC_DIR"/mpfr-*/
./configure --disable-shared --enable-static --prefix="$PREFIX" --with-gmp="$PREFIX"
make distclean && make && make check && make install

cd "$GCC_DIR"/mpc-*/
./configure --disable-shared --enable-static --prefix="$PREFIX" --with-gmp="$PREFIX" --with-mpfr="$PREFIX"
make distclean && make && make check && make install

#cd "$GCC_DIR"/libelf-*/
#./configure --disable-shared --enable-static --prefix="$PREFIX"
#make distclean && make && make check && make install

GCC_VER=$(echo "$GCC_DIR" | grep -o 'gcc-[0-9\.]\+' | sed 's/gcc-//')
GCC_BUILD_DIR=$GCC_DIR/../build-gcc-$GCC_VER
cd "$GCC_BUILD_DIR"
../gcc-"$GCC_VER"/configure \
	--target="$TARGET" \
	--prefix="$PREFIX" \
	--disable-libmudflap \
	--disable-libssp \
	--disable-libstcxx-pch \
  --disable-libstdcxx-pch \
	--disable-nls \
	--enable-interwork \
	--enable-languages=c,c++ \
	--enable-threads \
  --with-fpmath=sse \
  --with-gmp="$PREFIX" \
	--with-gnu-as \
	--with-gnu-ld \
  --with-mpc="$PREFIX" \
  --with-mpfr="$PREFIX"
make distclean && make && make install
