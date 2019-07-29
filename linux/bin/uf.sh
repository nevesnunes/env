filename_typed=$HOME/kb/typed.sh
filename_commands=$HOME/kb/commands.sh
filename_snippets=$HOME/kb/snippets.txt

pipe_typed="/tmp/uf-typed.pipe"
pipe_commands="/tmp/uf-commands.pipe"
pipe_snippets="/tmp/uf-snippets.pipe"
pipe_misc="/tmp/uf-misc.pipe"

cleanup() {
  rm -f \
    "$pipe_typed" \
    "$pipe_commands" \
    "$pipe_snippets" \
    "$pipe_misc"
}
trap cleanup EXIT SIGINT SIGTERM SIGUSR1

cleanup && mkfifo \
    "$pipe_typed" \
    "$pipe_commands" \
    "$pipe_snippets" \
    "$pipe_misc" || exit 1

args="$*"

function config-to-lists() {
  description=""
  action=""
  while read -r line; do
    # ignore blank lines
    if [[ "$line" =~ ^[[:space:]]*$ ]]; then
      continue
    fi

    # ignore comments between split action
    if [[ "$line" =~ ^# ]] && [[ -n "$action" ]]; then
      continue
    fi

    # remove non-printable characters
    line="$(echo -e "$line" | tr \
        -dc '[:alnum:][:space:][:punct:]')"

    # remove both leading and trailing spaces
    line="$(echo -e "$line" | sed \
        -e 's/^[[:space:]]*/usr/' \
        -e 's/[[:space:]]*$/usr/')"

    # line is a description
    if [[ "$line" =~ ^# ]]; then
      line="$(echo -e "$line" | sed \
          -e 's/#*[[:space:]]*/usr/')"
      # if we read a description in the previous line, append this to it
      if [[ -n "$description" ]]; then
        line=" $line"
      fi
      description+="$line"
    else
      # line is the start of an action
      if [[ "$line" =~ \\[[:space:]]*$ ]]; then
        line="$(echo -e "$line" | sed \
            -e 's/[[:space:]]*\\[[:space:]]*$/usr/')"
        action+="$line "
      # line is the end of an action
      else
        descriptions+=("$description")
        description=""
        action+="$line"
        actions+=("$action")
        action=""
      fi
    fi
  done < "$1"
}

function parse-typed() {
  local descriptions=()
  local actions=()
  config-to-lists "$filename_typed"
  typed_descriptions=("${descriptions[@]}")
  typed_actions=("${actions[@]}")

  size=${#typed_descriptions[@]}
  for (( i=0; i<=$size; i++ )); do
    echo "${typed_descriptions[$i]}" > \
      "$pipe_typed"
  done
}

function parse-commands() {
  local descriptions=()
  local actions=()
  config-to-lists "$filename_commands"
  command_descriptions=("${descriptions[@]}")
  command_actions=("${actions[@]}")

  size=${#command_descriptions[@]}
  for (( i=0; i<=$size; i++ )); do
    echo "${command_descriptions[$i]}" > \
      "$pipe_commands"
  done
}

function parse-snippets() {
  local descriptions=()
  local actions=()
  config-to-lists "$filename_snippets"
  snippet_descriptions=("${descriptions[@]}")
  snippet_actions=("${actions[@]}")

  size=${#snippet_descriptions[@]}
  for (( i=0; i<=$size; i++ )); do
    echo "${snippet_descriptions[$i]}" > \
      "$pipe_snippets"
  done
}

function parse-misc() {
  echo -e "$(apropos -s "1,8" -a "$args")" > \
    "$pipe_misc"
}

parse-commands &
parse-typed &
parse-snippets &
parse-misc &

if [[ -n "$args" ]]; then
  args="$args "
fi
result=$(parallel -j0 --line-buffer cat ::: \
    "$pipe_typed" \
    "$pipe_commands" \
    "$pipe_snippets" \
    "$pipe_misc" \
    | fzf -0 -1 -q "'$args")
if [[ $result == "" ]]; then
  exit 1
else
  # command
  size=${#command_descriptions[@]}
  for (( i=0; i<=$size; i++ )); do
    if [[ $result == "${command_descriptions[$i]}" ]] ; then
      echo "${command_actions[$i]}"
      eval "${command_actions[$i]}"
      exit 0
    fi
  done

  # typed
  size=${#typed_descriptions[@]}
  for (( i=0; i<=$size; i++ )); do
    if [[ $result == "${typed_descriptions[$i]}" ]] ; then
      txt="${typed_actions[$i]}"

      # Edit placeholders if they exist
      if echo "$txt" | grep -q -i '%%%'; then
        tmp_file=$(mktemp)
        trap 'rm -f "$tmp_file"' EXIT

        echo -n "$txt" > "$tmp_file"
        gvim -v -c "execute '/%%%' | call feedkeys('nvE', 'n')" "$tmp_file"
        txt=$(cat "$tmp_file")
      fi
      echo "$txt"
      eval "$txt"

      exit 0
    fi
  done

  # snippet
  size=${#snippet_descriptions[@]}
  for (( i=0; i<=$size; i++ )); do
    if [[ $result == "${snippet_descriptions[$i]}" ]] ; then
      echo -n "${snippet_actions[$i]}" | xclip -selection primary

      # Make sure the initial window gets the input
      id=$(xdotool getwindowfocus)
      xdotool windowunmap --sync "$id"

      xdotool key --clearmodifiers Shift+Insert

      # Ensure everything is typed before clipboards get cleaned on exit
      sleep 2
      exit 0
    fi
  done

  # apropos
  result=$(echo -e "$result" | awk '{print $1;}')
  eval "$result"
fi
