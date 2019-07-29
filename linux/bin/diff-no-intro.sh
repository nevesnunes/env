#!/usr/bin/env bash

set -eu

[ -d "$1" ]
[ -d "$2" ]

function list {
  while read -r i; do
    basename "$i" | \
      tr -d '\ \t' | \
      tr '[:upper:]' '[:lower:]' | \
      sed \
        -e 's/\(\[\|(\)[a-z0-9\ \t!+,_-]*\(\]\|)\)//g' \
        -e 's/\.[^\.]*$//' \
        -e 's/[^a-z0-9]*//g' >> "$2"
  done <<< "$(find "$1" -type f)"
}

t1=$(mktemp)
t2=$(mktemp)
trap '{ rm -f "$t1" "$t2"; }' EXIT

list "$1" "$t1"
list "$2" "$t2"
diff -Naurw <(sort -u "$t1") <(sort -u "$t2")
