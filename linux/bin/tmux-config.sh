#!/usr/bin/env sh

find_term() {
  find /usr/share/terminfo/ /lib/terminfo/ ~/.local/share/terminfo/ -type f \
    | grep "$1" 2> /dev/null
}

for i in xterm-256color xterm-16color xterm-color xterm linux; do
  test -n "$(find_term "$i")" && term=$i && break
done
if echo "$term" | grep -q 256; then
  # Requires: `tmux kill-server`
  tmux set -ag terminal-features ',*:256:hyperlinks:margins:overline:rectfill:RGB:sixel:strikethrough:usstyle'
  tmux set -ag terminal-overrides ',*:Ss=\E[%p1%d q:Se=\E[2 q'
  tmux set -ag terminal-overrides ',*:Sxl'
  tmux set -ag terminal-overrides ',*:Tc'
  tmux set-environment -g COLORTERM "truecolor"
fi
tmux set -g default-terminal "$term"

TMUX_VERSION=$(tmux -V \
  | gawk '/^\s*$/{next}; match($0, /tmux\s*([0-9\.]*)/, e) {print e[1]}')

# UTF8 is autodetected in 2.2 onwards, but errors if explicitly set
if [ "$(echo "$TMUX_VERSION < 2.2" | bc)" = 1 ]; then
  tmux set -g utf8 on \; set -g status-utf8 on \; set -g mouse-utf8 on
fi

if [ "$(echo "$TMUX_VERSION >= 2.4" | bc)" = 1 ]; then
  tmux bind -T copy-mode-vi y send-keys -X copy-pipe "xclip -in -selection clipboard"
  tmux bind y copy-mode \\\; send-keys '$' 'Space' '0' 'y' 'q'
else
  tmux bind -t vi-copy y copy-pipe "xclip -in -selection clipboard"
  tmux bind y copy-mode \\\; send-keys '$' 'Space' '0' 'y'
fi

if [ "$(echo "$TMUX_VERSION < 2.8" | bc)" = 1 ]; then
  # Colors
  tmux set -g pane-border-bg default
  tmux set -g pane-border-fg white
  tmux set -g pane-active-border-bg white
  tmux set -g pane-active-border-fg white
  tmux set -g status-bg default
  tmux set -g status-fg white

  # Active window title colors
  tmux setw -g window-status-current-fg blue
  tmux setw -g window-status-current-bg default
  tmux setw -g window-status-current-attr bright
else
  # Colors
  tmux set -g pane-border-style fg=white,bg=default
  tmux set -g pane-active-border-style fg=white,bg=white
  tmux set -g status-style fg=white,bg=default

  # Active window title colors
  tmux setw -g window-status-current-style fg=blue,bg=default,bright
fi
