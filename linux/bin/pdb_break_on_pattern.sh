#!/usr/bin/env bash

set -x

cleanup() {
  cp "$HOME"/.pdbrc-backup "$HOME"/.pdbrc
  rm "$HOME"/.pdbrc-backup
  trap - EXIT
}
trap cleanup EXIT HUP INT QUIT TERM

cp "$HOME"/.pdbrc "$HOME"/.pdbrc-backup

set -eu

echo '' > "$HOME"/.pdbrc
while read -r i; do
  file=$(echo "$i" | cut -d':' -f1)
  file=$(realpath "$file")
  lineno=$(echo "$i" | cut -d':' -f2)
  echo "break $file:$lineno" >> "$HOME"/.pdbrc
done <<< "$(grep -rin "$1" "$2")"
echo 'continue' >> "$HOME"/.pdbrc
shift
shift
python -m ipdb "$@"
