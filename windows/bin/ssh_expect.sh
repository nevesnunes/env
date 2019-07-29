#!/bin/bash

set -eux

pass=$1
shift

command -v "$1" &>/dev/null
if ! command -v expect &>/dev/null; then
  echo "WARN: Command 'expect' not found, running plain '$1'..."
  exec "$@"
fi

ssh_script=$(mktemp)
cleanup() {
  err=$?
  rm -f "$ssh_script"
  trap '' EXIT
  exit $err
}
trap cleanup EXIT INT QUIT TERM

cat <<- EOF > "$ssh_script"
#!/usr/bin/expect -f
#exp_internal 1
set timeout -1
set prompt "(%|#|\\\\\\\$) *$"
spawn $@
while 1 {
  expect {
    -re ".*assword:.*" {
      sleep 1
      exp_send -- "$pass\\r"
      exp_continue
    }
    "(yes/no)?" {
      exp_send "yes\\r"
      exp_continue
    }
    -re \$prompt { break }
    -re . { exp_continue }
    timeout { return 1 }
    eof { return 0 }
  }
}
interact
EOF

while true; do
  # Persist tunnel or interactive session on connection reset
  persist_pattern=$(printf '%s' \
    '^ssh[[:space:]]\+.*' \
    '\(-[LR][[:space:]]\+.*\|[^[:space:]]*@[^[:space:]]*\)' \
    '[[:space:]]*$')
  if echo "$@" | grep -q "$persist_pattern"; then
    # Don't exit on error
    "$ssh_script" "$@" || true

    # Give time for a user to cancel
    set +x
    for ((i=3; i>0; i--)) do
      echo "[$(basename "$0")] Reconnecting in $i seconds..."
      sleep 1
    done
    set -x
  else
    "$ssh_script" "$@" && exit
  fi
done
