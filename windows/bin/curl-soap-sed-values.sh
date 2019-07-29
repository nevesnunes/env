#!/usr/bin/env bash

set -eu

file_soap=$1
file_values=$2
url=$3

file_soap_replaced="$(mktemp)"

cleanup() {
  rm -f "$file_soap_replaced"
}
trap cleanup EXIT

while read -r l; do
  cp "$file_soap" "$file_soap_replaced"
  l=$(echo -n "$l" | tr -d '[:space:]')
  sed -i -e "s/PLACEHOLDER/$l/" "$file_soap_replaced"
  curl \
    -k -v \
    --header "Content-Type: text/xml;charset=UTF-8" \
    --data @"$file_soap_replaced" "$url"
done < "$file_values"
