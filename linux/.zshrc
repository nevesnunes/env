#zmodload zsh/zprof

export FPATH="$FPATH:$HOME/.local/share/completions/zsh"
import_dir="$HOME/bin/zsh"
[ -d "$import_dir/lib/" ] && for i in "$import_dir/lib/"*; do
    . "$i"
done
[ -d "$import_dir/themes/" ] && . "$import_dir/themes/fishier.zsh-theme"

# Completion
autoload -Uz compinit && compinit
compdef _gnu_generic binwalk fzf markdown-toc mountpoint openvpn xortool youtube-dl
setopt complete_aliases
setopt no_auto_remove_slash

# Directories
setopt auto_pushd
setopt pushd_ignore_dups
setopt pushdminus

# History
export HISTFILE=$HOME/.zsh_history
export HISTIGNORE="&:[ ]*:cd:cp:l[alrs]:mv:pwd*:[bf]g*:history*:clear:exit"
export HISTTIMEFORMAT='%s '
export HISTSIZE=50000
export SAVEHIST=20000
setopt append_history
setopt extended_history
setopt hist_expire_dups_first
setopt hist_ignore_all_dups
setopt hist_ignore_space
setopt hist_verify
setopt inc_append_history
setopt share_history

[ -f ~/.shrc ] && . ~/.shrc
[ -f ~/.fzf.zsh ] && . ~/.fzf.zsh
[ -f ~/opt/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh ] && \
    . ~/opt/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh

# Custom LS_COLORS was sourced after zsh plugin init
zstyle ':completion:*' list-colors "${(s.:.)LS_COLORS}"

#zprof

. "$HOME/.atuin/bin/env"
eval "$(atuin init zsh --disable-up-arrow)"
