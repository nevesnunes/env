#!/bin/sh

set -eux

./configure CPPFLAGS='-I/usr/include/ffmpeg'
make
sudo make install
