#!/usr/bin/env bash

function match() {
  echo "$1" | grep -i -E "$2"
}
export -f match
