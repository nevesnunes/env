#!/bin/sh

set -eux

. ./lib.sh

./linux-ctf.sh

sync_debian_packages ./debian-main.txt

# whipper
sudo apt install -y \
  flac swig \
  libcdio-dev libdiscid-dev libiso9660-dev libsndfile1-dev
sudo apt -t testing install -y \
  cd-paranoia
