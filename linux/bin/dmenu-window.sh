#!/usr/bin/env bash

set -eu

pattern='{
  gsub("[^\.]*\\.","",$3);
  gsub("'$(hostname)'\|[Nn]\/[Aa]",">",$4);
  printf("%s %-16s %s", $1, $3, substr($0,index($0,$4)));
}'
while read -r i; do
  options+=$(echo "$i" | awk "$pattern")'\n'
done <<< "$(wmctrl -lx)"
options=${options%\\n}

# Focus selected window
result=$(echo -e "$options" | \
  dmenu -f -i \
    -l 12 \
    -fn 'monospace-16' \
    -nb '#333' -nf '#fff' \
    -sb '#366ca2' -sf '#fff' | \
  cut -d' ' -f1)
[ -n "$result" ] && wmctrl -i -a "$result"
