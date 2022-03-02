# .bashrc

# . global definitions
[ -f /etc/bashrc ] && . /etc/bashrc

# Don't put duplicate lines or lines starting with space in the history
HISTCONTROL=ignoreboth:erasedups
HISTIGNORE="&:[ ]*:cd:cp:l[alrs]:mv:pwd*:[bf]g*:history*:clear:exit"
HISTTIMEFORMAT='%s '
HISTFILESIZE=20000
HISTSIZE=50000

# append to the history file, don't overwrite it
shopt -s histappend

# If set, a command name that is the name of a directory is executed as if it were the argument to the cd command. This option is only used by interactive shells.
shopt -s autocd

# If set, bash checks the window size after each external (non-builtin) command and, if necessary, updates the values of LINES and COLUMNS.
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

# Kill the word behind point, using white space and the slash character as the word boundaries.
bind '"\eq": unix-filename-rubout'

# Custom completions
complete -W "$([ -f Makefile ] && grep -oE '^[a-zA-Z0-9_-]+:([^=]|$)' Makefile | sed 's/[^a-zA-Z0-9_-]*$//')" make

completions_dir="$HOME/.local/share/completions/bash"
[ -d "$completions_dir" ] && for i in "$completions_dir/"*; do
    . "$i"
done

[ -f ~/.shrc ] && . ~/.shrc
if [ -f ~/.bash_prompt ]; then
    . ~/.bash_prompt
    PROMPT_COMMAND=prompt_main
fi
[ -f ~/.fzf.bash ] && . ~/.fzf.bash
[ -f ~/opt/bash-complete-partial-path/bash_completion ] && \
    . ~/opt/bash-complete-partial-path/bash_completion && \
    _bcpp --defaults

# Reset exit status for first prompt
:
