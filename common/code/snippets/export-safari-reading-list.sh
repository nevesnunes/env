#!/usr/bin/env sh

set -eux

iphone_dir=$(realpath "$1")
[ -d "$iphone_dir" ]
/usr/bin/plutil -convert xml1 -o - "$iphone_dir"/Library/Safari/Bookmarks.plist | \
  grep -E -o '<string>http[s]{0,1}://.*</string>' | \
  grep -v icloud | \
  sed -E 's/<\/{0,1}string>//g'
