#!/usr/bin/env sh

set -eu

tor.sh & disown

dir=${2:-"$HOME"/sandbox/opt/firefox-tor}
mkdir -p "$dir"
exec firefox -no-remote -profile "$dir"
