#!/bin/sh

# bpf re-implementation of https://justine.lol/ftrace/

# TODO: Use map to store level per tid

set -eu

bin=$(command -v "$1")
if ! [ -x "$bin" ]; then 
  echo "'$bin' not executable." >&2 
  exit 1
fi

uprobes=$(objdump --wide --dynamic-syms "$bin" \
  | awk '/DF.*LIBC/{print $NF}' \
  | sed 's_\(.*\)_uprobe:/usr/lib64/libc-2.33.so:\1_g' \
  | paste -sd',')
uretprobes=$(echo "$uprobes" | sed 's/uprobe:/uretprobe:/g')

sudo bpftrace -e '
  BEGIN { @level = 0; @start = nsecs; } 
  '"$uprobes"'
  /@start != 0 && pid == cpid/ { 
    @level++; 
    printf("%8d %8d ", tid, (nsecs - @start) / 1000);
    $i = 0;
    while ($i < @level - 1) { 
      if ($i > 10) { printf("+ "); break } 
      else { printf("  "); $i++ } 
    }
    printf("%s\n", func);
  }
  '"$uretprobes"'
  /@start != 0 && pid == cpid/ { @level--; }'  \
  -c "$*"