# TODO: Invocation which receives program to exec as argument/alias

function lf() {
  local result=$(lf-picker $*) 
  if [[ "$result" != 1 ]]; then
    lf-plumber "$result"
  else
    return 1
  fi
}

function lhf() {
    local likelyfiles=$(sed -nr 's/.*href="file:\/\/([^"]*)".*/\1/p' ~/.local/share/recently-used.xbel)"\n"
    likelyfiles+=$(find "." -maxdepth 1)
    result=$(echo -e "$likelyfiles" | fzf --tac -0 -1 -q "'$args " --prompt="likely files: ")

  if [[ "$result" != 1 ]]; then
    lf-plumber "$result"
  else
    return 1
  fi
}

function lif() {
  set -- "$PWD" $*
  local result=$(lf-picker $*) 
  if [[ "$result" != 1 ]]; then
    lf-plumber "$result"
  else
    return 1
  fi
}

function yf() {
  local args="$*"
  local result=$(lf-picker "$args") 
  if [[ "$result" != 1 ]]; then
    readlink -f "$result" | xclip -selection clipboard
  else
    return 1
  fi
}

function lf-picker() {
  local args="$*"

  # locate
  local result=''
  local locate_args=($(echo $args | sed -e 's/ /\n/g'))
  if [ $# -eq 0 ]; then
    result=$(locate -Ai -0 "" | grep -z -vE "~$" | fzf --read0 -0 -1)
  else
    result=$(locate -Ai -0 $locate_args | grep -z -vE "~$" | fzf --read0 -0 -1 -q "$args ")
  fi

  if [[ $? -gt 128 ]]; then
    return 1
  fi

  # likely
  if [[ $result == "" ]]; then
    local likelyfiles=$(sed -nr 's/.*href="file:\/\/([^"]*)".*/\1/p' ~/.local/share/recently-used.xbel)"\n"
    likelyfiles+=$(find "." -maxdepth 1)
    result=$(echo -e "$likelyfiles" | fzf --tac -0 -1 -q "'$args " --prompt="locate is clueless, let's try in likely files: ")
  fi

  if [[ $? -gt 128 ]]; then
    return 1
  fi

  # find
  if [[ $result == "" ]]; then
    local location=$(find "$HOME" -maxdepth 2 -not -path "*/\.*" -type d | fzf -0 -1 --prompt="still clueless, let's find in directory: ")

    if [[ $? -gt 128 ]]; then
      return 1
    fi

    local arg_array=($args)
    local arg_one=${arg_array[0]}
    result=$(find "$location" -name "*$arg_one*" | fzf -0 -1 -q "'$args ")

    # nothing
    if [[ $result == "" ]]; then
      return 1
    fi
  fi
  
  echo "$result"
}

function lf-plumber() {
  local result="$*"
  if [[ $result == "" ]]; then
    return 1
  fi

  local magicmime=$(file -b --mime-type $result)
  local mime=$(xdg-mime query filetype $result)
  if [[ $mime == "" ]]; then
    return 1
  fi

  # directory
  if [[ -d $result ]]; then
    cd -- "$result"

  # text 
  elif echo "$result" | grep -qiE "(docx?|odt)$" &&
       echo "$mime" | grep -qiE "application/zip"; then
    libreoffice "${result}" &
  elif echo "$mime" | grep -qiE "(application/javascript|text/|shell)(.*)$" ||
      echo "$magicmime" | grep -qiE "(text/plain)$"; then
    gvim -v "${result}"

  # archives
  elif echo "$result" | grep -qiE "(tar\.bz2|tbz2)$"; then
    tar xvjf "${result}"
  elif echo "$result" | grep -qiE "(tar\.gz|tgz)$"; then
    tar xvzf "${result}"
  elif echo "$result" | grep -qiE "(\.bz2)$"; then
    bunzip2 "${result}"
  elif echo "$result" | grep -qiE "(\.rar)$"; then
    unrar x "${result}"
  elif echo "$result" | grep -qiE "(\.gz)$"; then
    gunzip "${result}"
  elif echo "$result" | grep -qiE "(\.tar)$"; then
    tar xvf "${result}"
  elif echo "$result" | grep -qiE "(\.zip)$"; then
    unzip "${result}"
  elif echo "$result" | grep -qiE "(\.Z)$"; then
    uncompress "${result}"
  elif echo "$result" | grep -qiE "(\.7z)$"; then
    7z x "${result}"

  # anything
  else
    xdg-open "${result}" &
  fi
}
