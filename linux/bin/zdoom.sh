#!/usr/bin/env bash

set -e

# Runs on the directory with zdoom.pk3,
# with converted paths for other files.

args=()
while [ "$1" != "" ]; do
  case $1 in
    -file|-iwad)
      args+=("$1")
      shift
      file="$(pwd)/$1"
      [ -f "$file" ] || file="$(realpath "$1")"
      args+=("$file")
      ;;
    *)
      args+=("$1")
  esac
  shift
done

zdoom_bin=${ZDOOM_BIN:-zdoom}
zdoom_dir=${ZDOOM_DIR:-$HOME/opt/zdoom/build}

(
cd "$zdoom_dir"
exec ./"$zdoom_bin" "${args[@]}"
)
