#!/bin/sh
# shellcheck disable=SC2086

set -eu

c=$1
h=$2
out=$c$h
cp a.c0-80.h0-1.$c.$h.raw a.c0-80.h0-1.$c.$h.raw.0
mkdir -p ./$out
for i in $(seq 1 10); do
  gw read --revs 5 --seek-retries 1 --tracks c=$c:h=$h ./$out/a$i.00.0.raw --raw
  cp ./$out/a$i.$c.$h.raw ./a.c0-80.h0-1.$c.$h.raw
  gw convert --format=ibm.scan a.c0-80.h0-1.00.0.raw a-$c$h-$i.c0-80.h0-1.ibm.scan.img
done
