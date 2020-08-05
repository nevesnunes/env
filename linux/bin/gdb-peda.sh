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

cp "$HOME"/.gdbinit-peda "$HOME"/.gdbinit
gdb "$@"
