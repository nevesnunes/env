#!/bin/sh

set -eux

./configure --with-portaudio=local
make
sudo make install
