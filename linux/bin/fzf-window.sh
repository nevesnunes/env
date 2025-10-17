#!/usr/bin/env sh

set -eu

# `LC_ALL` is expected to be empty
LC_ALL=${LC_ALL:-}
LC_ALL=${SCRATCHPAD_TERMINAL_OLD_LC_ALL-${LC_ALL}}
export LC_ALL
LANG=${SCRATCHPAD_TERMINAL_OLD_LANG:-${LANG}}
export LANG

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
export FZF_DEFAULT_OPTS=
result=$(echo "$options" | \
 ~/opt/fzf/bin/fzf -0 -1 --color=16,pointer:2 --no-border | \
  cut -d' ' -f1)
[ -n "$result" ] && wmctrl -i -a "$result"
