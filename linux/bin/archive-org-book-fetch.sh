#!/usr/bin/env sh

set -u

url=$1
out=${2:-.}
mkdir -p "$out"

cookie='./cookies.txt'
if [ -z "$cookie" ]; then
  echo "Bad cookies"
  exit 1
fi

for i in $(seq -f "%04g" 0 270); do
  target="$out/$i.jp2"
  if [ -f "$target" ]; then
    echo "Skipping $target"
    continue
  fi

  url=$(echo "$url" | sed "s/_[0-9]\{4\}.jp2/_$i.jp2/")
  curl "$url" \
    --compressed -k -v \
    --cookie "$cookie" \
    --cookie-jar "$cookie" \
    -H 'User-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0' \
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
    -H 'Accept-Language: en,en-US;q=0.5' \
    -H 'Connection: keep-alive' \
    -H 'Upgrade-Insecure-Requests: 1' \
    -H 'Pragma: no-cache' \
    -H 'Cache-Control: no-cache' \
    > "$target"

  exit_code=$?
  if [ $exit_code -ne 0 ];then
    echo "Bad response"
    exit 1
  fi
  if [ -z "$target" ] || grep -qi 'doctype html' "$target"; then
    cat "$target"
    echo "Dowloaded junk for $target"
    rm "$target"
    exit 1
  fi

  rand_seconds=$(awk 'BEGIN { srand(); printf("%d\n", 5 * rand()) }')
  sleep "$rand_seconds"
done
