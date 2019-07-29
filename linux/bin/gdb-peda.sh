#!/usr/bin/env bash

cleanup() {
  cp "$HOME"/.gdbinit-backup "$HOME"/.gdbinit
  rm "$HOME"/.gdbinit-backup
}
trap cleanup EXIT

cp "$HOME"/.gdbinit "$HOME"/.gdbinit-backup
cp "$HOME"/.gdbinit-peda "$HOME"/.gdbinit
gdb "$@"
