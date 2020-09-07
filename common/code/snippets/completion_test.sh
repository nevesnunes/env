#!/bin/sh

if echo "$1" | grep -q -- '--help'; then
  echo '
  --foo: prints foo
  -f: prints f
  '
elif echo "$1" | grep -q -- '--foo'; then
  echo 'foo'
elif echo "$1" | grep -q -- '-f'; then
  echo 'f'
else
  echo ':('
fi
