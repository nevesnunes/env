#!/bin/sh

set -eux

build() {
  echo | abuild-keygen -a -i
  abuild -Fcr
}

apk update
apk add --no-cache \
  alpine-sdk autoconf automake binutils flex gawk gcc git libtool sudo \
  binutils-dev elfutils-dev libunwind-dev linux-headers musl-dev \
  bzip2-static libelf-static libunwind-static xz-static zlib-static zstd-static

# Manual build of libunwind static dependencies:
#
# cd /opt/aports/main/xz
# build
# cd ./src/
# tar -xzvf xz*tar.gz
# cd ./xz-*/
# ./autogen.sh
# ./configure
# cd ./src/liblzma
# make
# cp ./.libs/liblzma.a /usr/lib/
# 
# cd /opt/aports/main/libucontext
# build
# cd ./src/
# tar -xvf libucontext*tar.xz && rm -f libucontext*tar.xz
# cd ./libucontext*/
# make
# cp ./*.a /usr/lib/

script_pwd=$(realpath "$(dirname "$0")")
cd /opt
test -d ./aports || git clone --depth 1 --branch v3.20.0 git://git.alpinelinux.org/aports
cd /opt/aports/main/strace

# libunwind (1.8.1-r0)
git apply --recount "$script_pwd/strace606libunwind.diff"
build
tar -xzvf /root/packages/main/x86_64/strace-6.9-r0.apk
cp ./usr/bin/strace /share/static/strace609libunwind
