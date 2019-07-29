#!/usr/bin/env sh

cleanup() {
  cp "$HOME"/.gdbinit-backup "$HOME"/.gdbinit
  rm "$HOME"/.gdbinit-backup
  trap - EXIT
}
trap cleanup EXIT HUP INT QUIT TERM

cp "$HOME"/.gdbinit "$HOME"/.gdbinit-backup

set -eu

cp "$HOME"/.gdbinit-base "$HOME"/.gdbinit
gdb --tui "$@"
