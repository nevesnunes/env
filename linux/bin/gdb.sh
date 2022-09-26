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

if [ $# -gt 0 ]; then
  plugin_file=$(realpath "$1")
  if [ -f "$plugin_file" ]; then
    echo "source $plugin_file" >> "$HOME"/.gdbinit
    shift
  fi
fi

"$gdb_bin" -q "$@"
