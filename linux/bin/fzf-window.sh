#!/usr/bin/env sh

set -eu

pattern='{
  gsub("[^\.]*\\.","",$3);
  gsub("'$(hostname)'\|[Nn]\/[Aa]",">",$4);
  printf("%s %-16s %s", $1, $3, substr($0,index($0,$4)));
}'
ws=$(wmctrl -lx)
set -f; IFS='
'
options=''
for i in $ws; do
  set +f; unset IFS
  options="$options$(echo "$i" | awk "$pattern" 2>/dev/null)
"
done
set +f; unset IFS

# Focus selected window
result=$(echo "$options" | \
 ~/opt/fzf/bin/fzf -0 -1 --no-border | \
  cut -d' ' -f1)
[ -n "$result" ] && wmctrl -i -a "$result"
