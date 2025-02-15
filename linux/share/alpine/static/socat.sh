#!/bin/sh

set -eux

build() {
  echo | abuild-keygen -a -i
  abuild -F fetch verify
  abuild -Fcr
}

git apply --recount /share/alpine/static/socat.diff
export PKG_CONFIG=/bin/true

cd /opt/aports/main/socat
build
find /root/packages/main/x86_64/ -iname 'socat-[0-9]*apk' -exec cp {} "$PWD" \;
find . -iname 'socat-[0-9]*apk' -exec tar -xzvf {} \;
cp ./usr/bin/socat /share/
