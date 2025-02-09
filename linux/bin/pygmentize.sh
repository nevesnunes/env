#!/bin/sh

set -eu

if ! command -v pygmentize >/dev/null 2>&1; then
  exec cat "$@"
elif find ~/.local/lib/ -name pygments-paper.egg-link | grep -q .; then
  exec pygmentize -f paper "$@"
else
  exec pygmentize -f terminal "$@"
fi
