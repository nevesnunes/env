# .bashrc

# Source global definitions
[ -f /etc/bashrc ] && source /etc/bashrc

# Don't put duplicate lines or lines starting with space in the history
HISTCONTROL=ignoreboth:erasedups

HISTIGNORE="&:[ ]*:cd:pwd*:[bf]g*:history*:clear:exit"

HISTFILESIZE=20000
HISTSIZE=50000

# append to the history file, don't overwrite it
shopt -s histappend

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# If set, Bash lists the status of any stopped and running jobs before exiting an interactive shell. If any jobs are running, this causes the exit to be deferred until a second exit is attempted without an intervening command. The shell always postpones exiting if any jobs are stopped. 
shopt -s checkjobs

# If set, the pattern "**" used in a pathname expansion context will
# match all files and zero or more directories and subdirectories.
#shopt -s globstar

# Allow to review a history substitution result by loading the resulting line into the editing buffer, rather than directly executing it. 
shopt -s histverify

# Get immediate notification of background job termination
set -o notify

# Uncomment the following line if you don't like systemctl's auto-paging feature:
# export SYSTEMD_PAGER=

# User specific aliases and functions
# export TERM=xterm-256color

# Custom completions
complete -W "$([ -f Makefile ] && grep -oE '^[a-zA-Z0-9_-]+:([^=]|$)' Makefile | sed 's/[^a-zA-Z0-9_-]*$//')" make

# Imports
completions_dir="$HOME/.local/share/completions/bash"
[ -d "$completions_dir" ] && for i in "$completions_dir/"*; do
    source "$i"
done

if [ -f ~/.bash_prompt ]; then
    source ~/.bash_prompt
    PROMPT_COMMAND=prompt_main
fi
[ -f ~/.shrc ] && source ~/.shrc

[ -f ~/.fzf.bash ] && source ~/.fzf.bash

[ -f ~/opt/bash-complete-partial-path/bash_completion ] && \
    source ~/opt/bash-complete-partial-path/bash_completion && \
    _bcpp --defaults

# Reset exit status for first prompt
:
