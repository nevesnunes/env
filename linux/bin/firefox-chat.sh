#!/usr/bin/env sh

dir=${1:-"$HOME"/sandbox/opt/firefox-chat}
mkdir -p "$dir"
exec firefox -no-remote -profile "$dir"
