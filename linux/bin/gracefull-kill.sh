#!/usr/bin/env sh

(wmctrl -l | \
      grep -v -E "(xterm|scratchpad)" | \
      cut -d" " -f1 | \
      xargs -d'\n' -I{} -n1 -r wmctrl -i -c {}); \
    killall tmux; \
