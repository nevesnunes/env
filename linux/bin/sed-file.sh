#!/bin/sh

# Usage: sed-file.sh file key=value

set -eu

file=$1 ; shift

regex_escape () {
  printf %s\\n "$1" | sed -r 's/([][)(.*+^$/])/\\\1/g'
}
regex=''
for arg; do
  key=$(printf %s\\n "$arg" | cut -d:= -f1)
  regex="${regex}s/^$(regex_escape "$key")=.*$/$(regex_escape "$arg")/;"
done

exec sed -i -- "$regex" "$file"
