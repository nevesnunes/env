#!/bin/sh

set -eux

build() {
  echo | abuild-keygen -a -i
  abuild -F fetch verify
  abuild -Fcr
}

git apply --recount ~/share/alpine/static/strace.diff
export PKG_CONFIG=/bin/true

cd /opt/aports/main/xz
build
cd ./src/
tar -xzvf xz*tar.gz
cd ./xz-*/
./autogen.sh
./configure
cd ./src/liblzma
make
cp ./.libs/liblzma.a /usr/lib/

cd /opt/aports/main/libucontext
build
cd ./src/
tar -xvf libucontext*tar.xz && rm -f libucontext*tar.xz
cd ./libucontext*/
make
cp ./*.a /usr/lib/

cd /opt/aports/main/strace
build
#cd ./src/
#tar -xvf strace*tar.xz && rm -f strace*tar.xz
#cd ./strace*/
#./configure
#make
cp ./pkg/strace/usr/bin/strace /share/
