#!/bin/sh

set -eux

build() {
  echo | abuild-keygen -a -i
  abuild -F fetch verify
  abuild -F -r
}

git apply --recount ~/code/config/alpine/static.diff
export PKG_CONFIG=/bin/true

cd /opt/aports/main/xz
build
cd ./src/xz-5.2.5/src/liblzma
make
cp ./.libs/liblzma.a /usr/lib/

cd /opt/aports/main/libucontext
build
cp ./src/libucontext-1.1/*.a /usr/lib/

cd /opt/aports/main/strace
build
cp ./pkg/strace/usr/bin/strace /share/
