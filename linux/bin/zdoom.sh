#!/usr/bin/env bash

set -eu

# Runs on the directory with zdoom.pk3,
# with converted paths for other files.

args=()
while [ "$#" -gt 0 ]; do
  case $1 in
    -iwad)
      args+=("$1")
      shift
      file="$(pwd)/$1"
      [ -f "$file" ] || file="$(realpath "$1")"
      args+=("$file")
      ;;
    -file)
      args+=("$1")
      # Process multiple wads (e.g. btsx)
      while [ "$#" -gt 0 ]; do
        shift
        # Next argument is an option
        if echo "$1" | grep -q '^-'; then
          args+=("$1")
          break
        else
          file="$(pwd)/$1"
          [ -f "$file" ] || file="$(realpath "$1")"
          args+=("$file")
        fi
      done
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
