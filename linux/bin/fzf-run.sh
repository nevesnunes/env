#!/usr/bin/env sh

set -eu

# `LC_ALL` is expected to be empty
LC_ALL=${SCRATCHPAD_TERMINAL_OLD_LC_ALL-${LC_ALL}}
export LC_ALL
LANG=${SCRATCHPAD_TERMINAL_OLD_LANG:-${LANG}}
export LANG

cmd=$(IFS=: command eval 'stest -flx $PATH' | \
  awk '!a[$1]++' | \
  ~/opt/fzf/bin/fzf -0 -1 --no-border)
command -v "$cmd" >/dev/null 2>&1 && exec sh -c -i "nohup $cmd &"
