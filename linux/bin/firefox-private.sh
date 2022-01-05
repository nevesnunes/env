#!/usr/bin/env sh

dir=${1:-"$HOME"/sandbox/opt/firefox-private}
mkdir -p "$dir"
exec firefox -no-remote -private -profile "$dir"
