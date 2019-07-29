# Source:
# https://www.reddit.com/r/linux/comments/5uru1g/martin_graesslin_editing_files_as_root/

# Sync changes:
# pkill -x -USR1 unprivopen

#!/bin/bash

set -eu

sudo=sudo # binary we use for privilege escalation

prog="$1"
args=( "${@:2}" )
if [[ ${#args[@]} -le 0 ]]; then
    echo "needs an argument to open" >&2
    exit 2
    fi

last=$(( ${#args[@]} - 1 )) # last argument given is always the file to open

filename=${args[last]}

tmpdir=$(mktemp -t ${XDG_RUNTIME_DIR+"-p" "$XDG_RUNTIME_DIR"} -d unprivopen.XXXX)

tmpfile="$tmpdir/$(basename -- "$filename").tmp"
args[last]="$tmpfile" # be sure to change the argv with our modified path to the tempfile

cp -Tf -- "$filename" "$tmpfile"

syncer () { # syncs the tmpfile with the actual file
    if ! diff "$tmpfile" "$filename"; then
        $sudo dd "if=$tmpfile" "of=$filename" # we use dd instead of cp to retain the old file permissions
    else
        echo "no changes detected" >&2
        exitc=1
        fi
    }

cleaner () { # cleans up old garbage
    syncer
    rm    -- "$tmpfile"
    rmdir -- "$tmpdir"

    exit ${exitc-0}
    }


trap syncer USR1
trap cleaner EXIT

"$prog" "${args[@]}" &

while [ -n "$(jobs)" ]; do
    wait || true
    done
