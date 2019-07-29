#!/usr/bin/env bash

# Run `pylint` by extracting python version from the interpreter name,
# present in the scritp's shebang.

PYLINT_ARGS=($@)
FILE_TO_LINT=${PYLINT_ARGS[${#PYLINT_ARGS[@]}-1]}

# Wait for file to be accessible
SHEBANG=""
TRIES=4
while [[ $TRIES -gt 0 ]]; do
  SHEBANG="$(head -n1 "$FILE_TO_LINT")"
  if [ -n "$SHEBANG" ]; then
    break
  fi
  TRIES=$(($TRIES - 1))
  sleep 1
done

PY_VERSION=$(echo "$SHEBANG" | \
    grep -oE "python.*" | \
    grep -oE "[0-9.]*")
if [ -z "$PY_VERSION" ]; then
  PY_VERSION=3
fi
if [ "$(echo "$PY_VERSION < 3" | bc)" = 1 ]; then
  python2 -m pylint "$@"
else
  python3 -m pylint "$@"
fi
