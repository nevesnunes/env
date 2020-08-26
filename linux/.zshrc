#zmodload zsh/zprof

ZSH_THEME="fishier"
import_dir="$HOME/bin/zsh"
[ -d "$import_dir/lib/" ] && for i in "$import_dir/lib/"*; do
    source "$i"
done
[ -d "$import_dir/themes/" ] && for i in "$import_dir/themes/"*; do
    source "$i"
done

autoload -Uz compinit && compinit
compdef _gnu_generic fzf

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

setopt auto_pushd
setopt pushd_ignore_dups
setopt pushdminus

setopt complete_aliases
setopt no_auto_remove_slash

[ -f ~/.shrc ] && source ~/.shrc
[ -f ~/.fzf.zsh ] && source ~/.fzf.zsh
[ -f ~/opt/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh ] && \
    source ~/opt/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh

#zprof
