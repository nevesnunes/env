#!/bin/sh

set -eux

. ./lib.sh

debloat
sync_debian_packages ./ubuntu-ctf.txt
