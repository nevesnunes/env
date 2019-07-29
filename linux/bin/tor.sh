#!/usr/bin/env sh

set -eu

torbrowser_dir=/home/fn/.local/share/torbrowser/tbb/x86_64/tor-browser_en-US/Browser/TorBrowser
defaults_torrc="$torbrowser_dir/Data/Tor/torrc-defaults"
torrc=${1:-"$torbrowser_dir/Data/Tor/torrc"}
if ! pgrep --list-name tor | grep -qi '\stor$'; then
  LD_LIBRARY_PATH="$torbrowser_dir/Tor" "$torbrowser_dir/Tor/tor" \
    --defaults-torrc "$defaults_torrc" \
    -f "$torrc" & disown
fi
