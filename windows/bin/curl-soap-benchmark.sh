#!/usr/bin/env bash

set -eu

file_soap=$1
url=$2

tmpfile=$(mktemp)
sortedtmpfile=$(mktemp)
trap 'rm $tmpfile $sortedtmpfile' INT QUIT TERM

for i in {1..50}; do
  curl -s -w '%{time_total}\n' -o /dev/null \
    -k \
    --header "Content-Type: text/xml;charset=UTF-8" \
    --data @"$file_soap" "$url" >> "$tmpfile"
done

cat "$tmpfile"
sort -u "$tmpfile" > "$sortedtmpfile"
awk 'NR == 1 {min = $0} $0 > max {max = $0} {total += $0} END {print "avg:", total/NR, "min:", min, "max:", max}' "$sortedtmpfile"
