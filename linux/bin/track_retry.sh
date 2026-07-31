#!/bin/sh

set -eu

c=$1
h=$2
name=${3:-a.c0-80.h0-1}

out=$c$h
cp "$name.$c.$h.raw" "$name.$c.$h.raw.0"
mkdir -p ./"$out"
for i in $(seq 1 10); do
  gw read --revs 10 --seek-retries 2 --tracks "c=$c:h=$h" ./"$out/a$i.00.0.raw" --raw
  cp ./"$out/a$i.$c.$h.raw" ./"$name.$c.$h.raw"
  gw convert --format=ibm.scan "$name.00.0.raw" "a-$c$h-$i.ibm.scan.img"
done
