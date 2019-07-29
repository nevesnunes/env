# ZSH Theme emulating the Fish shell's default prompt.

_fishy_collapsed_wd() {
  echo $(pwd | perl -pe '
   BEGIN {
      binmode STDIN,  ":encoding(UTF-8)";
      binmode STDOUT, ":encoding(UTF-8)";
   }; s|^$ENV{HOME}|~|g; s|/([^/.])[^/]*(?=/)|/$1|g; s|/\.([^/])[^/]*(?=/)|/.$1|g
')
}

_jobs_info() {
    count_jobs=$( (jobs -l) | wc -l)
    if [[ $count_jobs -gt 0 ]]; then
        echo " [$count_jobs]"
    else
        echo ""
    fi
}

local user_color='green'; [ $UID -eq 0 ] && user_color='red'
local return_status="%{$fg_bold[red]%}%(?..%? )%{$reset_color%}"

PROMPT='%{$fg[$user_color]%}$(_fishy_collapsed_wd)%{$reset_color%}$(git_prompt_info)$(_jobs_info) $return_status%{$reset_color%}%{$fg_bold[green]%}▬▬▬▬ %{$reset_color%}'
PROMPT2='%{$fg[red]%} %{$reset_color%}'

ZSH_THEME_GIT_PROMPT_PREFIX=" ("
ZSH_THEME_GIT_PROMPT_SUFFIX=")"
ZSH_THEME_GIT_PROMPT_DIRTY="*"
ZSH_THEME_GIT_PROMPT_CLEAN=""
