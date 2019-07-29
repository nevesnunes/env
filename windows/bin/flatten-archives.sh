#!/bin/sh

# References
# https://github.com/ranger/ranger/blob/master/ranger/config/rifle.conf

set -eux

find_candidates() {
  find "$1" -iregex '.*\.\(bz2?\|gz\|tar\|xz\|zip\|jar\|war\|ear\|7z\|ace\|ar\|arc\|cab\|cpio\|cpt\|deb\|dgc\|dmg\|iso\|msi\|pkg\|rar\|shar\|tgz\|xar\|xpi\)' | \
    wc -l
}

flatten() {
  find "$1" -iregex '.*\.\(bz2?\|gz\|tar\|xz\)' -exec env SHELLOPTS=xtrace sh -c '
  (
    expanded_dirname="$(realpath "$1" | sed "s/\.[^\.]*$//")" && \
    mkdir -p "$expanded_dirname" && \
    cd "$(dirname "$(realpath "$1")")" && \
    tar vvxf -C "$expanded_dirname" "$1" && \
    rm -f "$1"
  )
  ' _ {} \;
  find "$1" -iregex '.*\.\(zip\|jar\|war\|ear\)' -exec env SHELLOPTS=xtrace sh -c '
  (
    expanded_dirname="$(realpath "$1" | sed "s/\.[^\.]*$//")" && \
    mkdir -p "$expanded_dirname" && \
    cd "$(dirname "$(realpath "$1")")" && \
    unzip -d "$expanded_dirname" -o "$1" && \
    rm -f "$1"
  )
  ' _ {} \;
  find "$1" -iregex '.*\.\(7z\|ace\|ar\|arc\|cab\|cpio\|cpt\|deb\|dgc\|dmg\|iso\|msi\|pkg\|rar\|shar\|tgz\|xar\|xpi\)' -exec env SHELLOPTS=xtrace sh -c '
  (
    expanded_dirname="$(realpath "$1" | sed "s/\.[^\.]*$//")" && \
    mkdir -p "$expanded_dirname" && \
    cd "$(dirname "$(realpath "$1")")" && \
    atool --extract-to="$expanded_dirname" "$1" && \
    rm -f "$1"
  )
  ' _ {} \;
}

target_dir=$(realpath "$PWD")
candidates=$(find_candidates "$target_dir")
while [ "$candidates" -gt 0 ]; do
  flatten "$target_dir"
  candidates=$(find_candidates "$target_dir")
done
