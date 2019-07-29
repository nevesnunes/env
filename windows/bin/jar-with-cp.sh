#!/bin/sh

set -eux

jar_bin=$1
[ -f "$jar_bin" ]
jar_dir=$2
[ -d "$jar_dir" ]
main_class=${3:-}

cp=$(find "$jar_dir" -iname '*.jar' -exec dirname {} \; | \
  sort -u | \
  sed 's/$/\/*/' | \
  paste -sd ':' -)
cp=".:$cp"
[ -z "$main_class" ] && \
  main_class=$(unzip -c "$jar_bin" META-INF/MANIFEST.MF | \
  awk '/Main-Class/ { print $2 }')
jar_bin_dir=$(dirname "$jar_bin")
(
  cd "$jar_bin_dir"
  java -cp "$cp" "$main_class"
)
