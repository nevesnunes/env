#!/usr/bin/env bash

dir=$1
if [ -z "$1" ]; then
  dir=$PWD
fi
tree -tf --noreport -I '*~' --charset ascii "$dir" |
    sed \
      -e 's/| \+/  /g' \
      -e 's/[|`]-\+/ */g' \
      -e 's:\(* \)\(\(.*/\)\([^/]\+\)\):\1[\4](\2):g'
