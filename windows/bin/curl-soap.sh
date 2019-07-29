#!/usr/bin/env bash

set -eu

file_soap=$1
url=$2

curl \
  -k -v \
  --header "Content-Type: text/xml;charset=UTF-8" \
  --data @"$file_soap" "$url"
