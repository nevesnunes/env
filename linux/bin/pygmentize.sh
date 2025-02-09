#!/bin/sh

set -eu

if ! command -v pygmentize > /dev/null 2>&1; then
  exec cat "$@"
else
  if find ~/.local/lib/ -name pygments-paper.egg-link | grep -q .; then
    formatter=paper
  else
    formatter=terminal
  fi

  if test -f "$1" && (echo "$1" | grep -q '\.bin$' || file --mime-type "$1" | grep -q 'application/octet-stream'); then
    exec xxd -l 4096 "$1" | pygmentize -f "$formatter" -l hexdump
  else
    exec pygmentize -f "$formatter" "$@"
  fi
fi
