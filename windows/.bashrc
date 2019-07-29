# .bashrc

# Source global definitions
if [ -f /etc/bashrc ]; then
	. /etc/bashrc
fi

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
HISTCONTROL=ignoreboth:erasedups

HISTIGNORE="pwd*:[bf]g*:history*:clear:exit:ls"

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=20000
HISTFILESIZE=20000

# skip typing `cd`
shopt -s autocd

# append to the history file, don't overwrite it
shopt -s histappend

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# If set, Bash lists the status of any stopped and running jobs before exiting an interactive shell. If any jobs are running, this causes the exit to be deferred until a second exit is attempted without an intervening command. The shell always postpones exiting if any jobs are stopped. 
shopt -s checkjobs

# If set, the pattern "**" used in a pathname expansion context will
# match all files and zero or more directories and subdirectories.
shopt -s globstar

# If a pattern fails to match, bash reports an expansion error.
shopt -s failglob

# Allow to review a history substitution result by loading the resulting line into the editing buffer, rather than directly executing it. 
shopt -s histverify

# Get immediate notification of background job termination
set -o notify

# Uncomment the following line if you don't like systemctl's auto-paging feature:
# export SYSTEMD_PAGER=

# User specific aliases and functions
# export TERM=xterm-256color

alias ..='cd ..'
alias ctags="ctags \
    --exclude='*.hg*' \
    --exclude='*.cvs*' \
    --exclude='*.svn*' \
    --exclude='*.git*' \
    --exclude='*public_html*' \
    --exclude='*bower_components*' \
    --exclude='*node_modules*' \
    --exclude='*.DS_Store*' \
    --exclude='*.min.js' \
    --exclude='*.min.css' \
    --exclude='tags' \
    --exclude='TAGS' \
    --exclude='GTAGS' \
    --exclude='GPATH' \
    --exclude='GRTAGS' \
"
alias ls='ls --color=auto'
alias la='ls -lA'
alias ll='ls -l'
alias lr='ls -latrh'
alias rm='rm -I'
alias grep='grep --color=auto --exclude=tags --exclude-dir=.git --exclude-dir=.svn'
alias notify-send='echo'
alias noise='sox -n -t waveaudio 0 synth brownnoise synth pinknoise band -n 2500 6000 reverb vol 0.8'
alias o='start ""'
alias xdg-open='start ""'

# `-T 1C`: Parallel builds: use 1 thread per available CPU core
command -v mvn >/dev/null 2>&1 && \
    [ "$(mvn --version | \
        awk '{
            if (match($0, /Apache Maven ([3-9])/, r)) 
                print r[1]
        }')" -gt 2 ] && \
    alias mvn='mvn -T 1C'

source ~/.profile-ssh_agent
source ~/opt/z.sh

command -v git >/dev/null 2>&1 && \
    git config --global core.excludesfile "$HOME/.gitignore_global" 

if [[ "$TERM" == cygwin ]]; then
    export PATH=/c/Strawberry/perl/bin:$PATH:$HOME/lib:/c/Program\ Files/SlikSvn/bin:/c/Program\ Files/nodejs:$HOME/AppData/Roaming/npm:$HOME/node_modules/.bin:/c/ProgramData/chocolatey/bin:"$(ruby -rubygems -e "puts Gem.user_dir")"/bin
    export PYTHON_PATH_PREFIX='/c'
    export EXEC_PTY=''
    [ -f ~/.fzf.bash ] && source ~/.fzf.bash
else
    export PYTHON_PATH_PREFIX='c:'
    export EXEC_PTY='winpty -Xplain -Xallow-non-tty'
    # FIXME: winpty does not allow stdin to be piped
    # [ -f ~/.fzf.bash ] && source ~/.fzf.bash
    # fzf_bin=$(command -v fzf 2>/dev/null)
    # if [ -x "$fzf_bin" ]; then
    #     fzf() {
    #         winpty -Xallow-non-tty env TERM=cygwin "$fzf_bin" "$@"
    #     }
    #     export -f fzf
    # fi
    [ -f ~/.fzy-key-bindings.bash ] && source ~/.fzy-key-bindings.bash
fi
if [[ "$MSYSTEM" == MINGW* ]]; then
    #export PYTHON2_PATH="$PYTHON_PATH_PREFIX/Python27"
    #export PYTHON3_PATH="$PYTHON_PATH_PREFIX/Python36"
    #alias python2="PYTHONHOME=$PYTHON2_PATH PYTHONPATH=$PYTHON2_PATH/Lib $EXEC_PTY $PYTHON2_PATH/python"
    #alias python3="PYTHONHOME=$PYTHON3_PATH PYTHONPATH=$PYTHON3_PATH/Lib $EXEC_PTY $PYTHON3_PATH/python"

    ## Use python3 by default
    #export PYTHONHOME=$PYTHON3_PATH 
    #export PATH="$PATH:$PYTHONHOME/Scripts"
    alias python=python3

    # z3
    export PATH="$HOME/lib/z3-4.8.4.d6df51951f4c-x64-win/bin:$PATH"
    export PYTHONPATH="$HOME/lib/z3-4.8.4.d6df51951f4c-x64-win/bin:$HOME/lib/z3-4.8.4.d6df51951f4c-x64-win/bin/python:/usr/lib/python3.7/site-packages"
elif [[ "$MSYSTEM" == MSYS* ]]; then
    export PATH="$PATH:/mingw64/bin:/mingw32/bin"
fi

for i in ~/bin/functions/*.sh; do
    . "$i"
done
