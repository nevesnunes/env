#!/usr/bin/env bash

# Create associated source files for header files

set -eu

for fn in $(comm -23 \
  <(ls *.h      |cut -d '.' -f 1|sort) \
  <(ls *.c *.cpp|cut -d '.' -f 1|sort)); do
  echo "#include \"$fn.h\"" >> "$fn".cpp
done
