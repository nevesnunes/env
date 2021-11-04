#!/bin/sh

cleanup() {
  err=$?
  cp "$HOME"/.gdbinit-backup "$HOME"/.gdbinit
  rm "$HOME"/.gdbinit-backup
  trap '' EXIT
  exit $err
}
trap cleanup EXIT INT QUIT TERM

cp "$HOME"/.gdbinit "$HOME"/.gdbinit-backup

set -eu

echo "source ~/.gdbinit-base" > "$HOME"/.gdbinit

gdb_bin=$(realpath "$1")
[ -f "$gdb_bin" ]
shift

while [ $# -gt 0 ]; do
  plugin_file=$(realpath "$1")
  [ -f "$plugin_file" ]
  echo "source $plugin_file" >> "$HOME"/.gdbinit
  shift
done

"$gdb_bin" -q "$@"
