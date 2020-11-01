#!/bin/sh

set -eux

convert -depth 8 "$1" rgb:1.part
convert -depth 8 "$2" rgb:2.part
cat 1.part 2.part > yt_dl-2020.9.20.tar.gz
rm -f 1.part 2.part
