#!/usr/bin/env sh

set -eu

tmp_file=$(mktemp)
"$@" > "$tmp_file"
cygpath -w "$tmp_file"
