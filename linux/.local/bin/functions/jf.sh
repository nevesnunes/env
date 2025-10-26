function zf() {
  local original_pwd="$PWD"
  local args="$*"
  if [[ -z $args ]]; then
    return 1
  fi

  local has_permutations=true
  command -v permutations.sh > /dev/null 2>&1
  if [[ $? -eq 1 ]]; then
    has_permutations=false
  fi

  local success=false
  if [[ "$has_permutations" == true ]]; then
    local args_permutations=$(permutations.sh $args)
    while read -r i; do
      z "$i"
      if [[ $? -ne 1 ]]; then
        success=true 
        break
      fi
    done <<< "$args_permutations"
  else
    z $args
    if [[ $? -ne 1 ]]; then
      success=true 
    fi
  fi

  local current_pwd="$PWD"
  if [[ "$success" == false ]] || \
      [[ "$original_pwd" == "$current_pwd" ]]; then
    jf $args
  else
    ls
  fi
}

function jif() {
  set -- "$PWD" $*
  jf $*
}

function jf() {
  local finder=bfs
  command -v bfs > /dev/null 2>&1
  if [[ $? -eq 1 ]]; then
    finder=find
  fi

  local args="$*"

  # locate
  local output=''
  local locate_args=($(echo $args | sed -e 's/ /\n/g'))
  if [[ $# -eq 0 ]]; then
    output=$(locate -Ai -0 "" | grep -z -vE '~$' | fzf --read0 -0 -1 \
        --prompt="[ctrl-f: open in file manager]: " --expect=ctrl-f)
  else
    output=$(locate -Ai -0 $locate_args | grep -z -vE '~$' | fzf --read0 -0 -1 \
        --prompt="[ctrl-f: open in file manager]: " -q "$args " --expect=ctrl-f)
  fi
  if [[ $? -gt 128 ]]; then
    return 1
  fi

  # Try parent directories
  local file=$(echo "$output" | sed -n "2p")
  if [[ $file == "" ]]; then
    local next_parent="$PWD"
    while [[ "$next_parent" != "/" ]]; do
      output=$("$finder" "$next_parent" -maxdepth 1 -mindepth 1 -type d | fzf -0 -1 \
          --prompt="[ctrl-f: open in file manager]: " -q $args --expect=ctrl-f)
      if [[ $? -gt 128 ]]; then
        break
      fi

      file=$(echo "$output" | sed -n "2p")
      if [[ $file != "" ]]; then
        break
      fi

      next_parent="$(readlink -f $next_parent/..)"
    done

    # find
    if [[ $file == "" ]]; then
      local location=$("$finder" "$HOME" -maxdepth 2 -not -path "*/\.*" -type d | \
          fzf -0 -1 --prompt="locate is clueless, let's find in dir: ")
      if [[ $? -gt 128 ]]; then
        return 1
      fi

      local arg_array=($args)
      local arg_one=${arg_array[0]}
      output=$("$finder" "$location" -name "*$arg_one*" | fzf -0 -1 -q "'$args " \
          --prompt="[ctrl-f: open in file manager]: " --expect=ctrl-f)

      # nothing
      file=$(echo "$output" | sed -n "2p")
      if [[ $file == "" ]]; then
        return 1
      fi
    fi
  fi

  if [[ -n $file ]]; then
    local target="$file"
    if ! [[ -d $file ]]; then
      target=${file:h}
    fi

    local action=$(echo "$output" | sed -n "1p")
    if [[ $action == "" ]]; then
      cd -- $target
      ls
    else
      nautilus $target &
    fi
  fi
}
