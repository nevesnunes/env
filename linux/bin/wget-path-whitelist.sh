#!/bin/sh

set -eu

url=${1%/}/
wget \
  --adjust-extension \
  --convert-links \
  -e robots=off \
  --limit-rate=500k --random-wait --wait=0.2 \
  --no-parent \
  --no-use-server-timestamps \
  --recursive \
  --spider \
  "$url" | \
  grep -oE "$url.*"
