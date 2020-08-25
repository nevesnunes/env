#!/bin/sh

# Share session

# From client 1:
ssh foo@bar
tmux

# From client 2:
ssh foo@bar
tmux attach

# Debug terminal colors in tmux
tmux new-session 'echo $TERM > /tmp/a && tput colors >> /tmp/a' && cat /tmp/a && rm /tmp/a

# Switch to pane containing open file
# Alternative: ts()
# https://unix.stackexchange.com/questions/309660/is-it-possible-to-find-which-vim-tmux-has-my-file-open
FNAME=~/tmp/git.md.swp; tmux switch -t $(tmux list-panes -a -F '#{session_name}:#{window_index}.#{pane_index} #{pane_tty}' | grep $(ps -o tty= -p $(lsof -t $FNAME))$ | awk '{ print $1 }')

# copy paste
# 1. enter copy mode = [
# 2. select = V
# 3. copy = Enter || y


