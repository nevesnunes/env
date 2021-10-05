# Reference: https://akikoskinen.info/image-diffs-with-git/
diff_img() {
  compare "$2" "$1" png:- \
    | montage -geometry +4+4 "$2" - "$1" png:- \
    | display -title "$1" -
}

diff_dirs() {
  tree1=$(mktemp)
  tree2=$(mktemp)
  tree -d -L 3 "$1" > "$tree1"
  tree -d -L 3 "$2" > "$tree2"
  vim -d "$tree1" "$tree2"
  rm -f "$tree1" "$tree2"
}

dup_dirs() {
  find "$1" -type f -exec basename {} \; \
    | sed 's/\(.*\)\..*/\1/' \
    | sort \
    | uniq -c \
    | grep -v "^[ \t]*1 "
}

ssh() {
  # grep -w: match command names such as "tmux-2.1" or "tmux: server"
  if ps -p $$ -o ppid= \
    | xargs -i ps -p {} -o comm= \
    | grep -qw tmux; then
    # Note: Options without parameter were hardcoded,
    # in order to distinguish an option's parameter from the destination.
    #
    #                   s/[[:space:]]*\(\( | spaces before options
    #     \(-[46AaCfGgKkMNnqsTtVvXxYy]\)\| | option without parameter
    #                     \(-[^[:space:]]* | option
    # \([[:space:]]\+[^[:space:]]*\)\?\)\) | parameter
    #                      [[:space:]]*\)* | spaces between options
    #                        [[:space:]]\+ | spaces before destination
    #                \([^-][^[:space:]]*\) | destination
    #                                   .* | command
    #                                 /\6/ | replace with destination
    tmux rename-window "$(echo "$@" \
      | sed 's/[[:space:]]*\(\(\(-[46AaCfGgKkMNnqsTtVvXxYy]\)\|\(-[^[:space:]]*\([[:space:]]\+[^[:space:]]*\)\?\)\)[[:space:]]*\)*[[:space:]]\+\([^-][^[:space:]]*\).*/\6/')"
    command ssh "$@"
    tmux set-window-option automatic-rename "on" 1> /dev/null
  else
    command ssh "$@"
  fi
}

# rcfile in a hosted folder:
# python2 -m SimpleHTTPServer 12345
sshrc() {
  ssh -R 12345:127.0.0.1:12345 -t "$@" 'bash -c "bash --rcfile <(curl -s http://127.0.0.1:12345/sshrc)"'
}

verify_certificate() {
  curl --insecure -v "$1" 2>&1 | awk 'BEGIN { cert=0 } /^\* Server certificate:/ { cert=1 } /^\*/ { if (cert) print }'
}

man_cat() {
  #groff -te -mandoc -rHY=0 -Tascii <(zcat "$1") | sed -e "s/\x1b\[[^m]\{1,5\}m//g" | col -bx
  #find . -iname '*fc*' -print0 | xargs -0 -i sh -c 'zcat "$1" | grep -in charset && echo "$1"' _ {} | vim -
  find /usr/share/man -iname '*'"$1"'*gz' -print0 \
    | xargs -0 -i zcat {} \
    | groff -te -mandoc -rHY=0 -Tascii 2> /dev/null \
    | grep -i "$2"
}

jar_decompile() {
  while [ $# -gt 0 ]; do
    jar -xf "$1" && find . -iname "*.class" -print0 \
      | xargs -0 -i jad -r {}
    shift
  done
}

e() {
  lines=
  while IFS= read -r i; do
    if [ -n "$lines" ]; then
      lines="$lines\n$i"
    else
      lines="$i"
    fi
  done
  while true; do
    filename=$(printf "%b" "$lines" | fzf -0)
    if [ -n "$filename" ]; then
      gvim -v "$filename" < /dev/tty
    else
      break
    fi
  done
}

# Edit pipe.
# Reference: http://git.ankarstrom.se/xutil/tree/ep
ep() {
  tmp_dir=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
  tmp=$(mktemp "$tmp_dir"/ep.XXXXXX)
  cat > "$tmp"
  gvim -v "$tmp" < /dev/tty > /dev/tty
  cat "$tmp"
  rm "$tmp"
}

f() {
  find . \
    ! -path '*/.bzr/*' \
    ! -path '*/.git/*' \
    ! -path '*/.hg/*' \
    ! -path '*/.svn/*' \
    ! -path '*/__pycache__/*' \
    ! -path '*/node_modules/*' \
    -iname '*'"$*"'*'
}

# `grep` with synonym expansion.
s() {
  database=$HOME/code/data/synonyms.txt
  query="$*"
  for word in "$@"; do
    # Iterate through regex alternatives by substituting on `|`.
    # To handle cases where no `|` character is present, force a first pass.
    remainder="$word"
    first="${remainder%%|*}"
    remainder="${remainder#*|}"
    if [ "$first" = "$remainder" ]; then
      remainder=
    fi
    while [ -n "$first" ] || [ "$first" != "$remainder" ]; do
      synonyms=$(grep -iw -- "$first" "$database" 2> /dev/null | paste -sd'|')
      if [ -n "$synonyms" ]; then
        query=$(echo "$query" | sed 's/\b'"$first"'\b/('"$synonyms"')/g')
      fi

      first="${remainder%%|*}"
      remainder="${remainder#*|}"
      if [ "$first" = "$remainder" ]; then
        remainder=
      fi
    done
  done

  g "$query"
}

# `grep` with intermediate binary files conversion to plaintext.
g() {
  if command -v rg > /dev/null 2>&1; then
    rg --smart-case \
      --follow \
      --max-columns 500 \
      --max-columns-preview \
      --no-heading \
      --with-filename \
      --line-number \
      --glob '!.bzr/' \
      --glob '!.git/' \
      --glob '!.hg/' \
      --glob '!.svn/' \
      --glob '!__pycache__/' \
      --glob '!node_modules/' \
      "$@" .
  else
    grep -Rin \
      --binary-files=without-match \
      --extended-regexp \
      --exclude-dir='.bzr' \
      --exclude-dir='.git' \
      --exclude-dir='.hg' \
      --exclude-dir='.svn' \
      --exclude-dir='__pycache__' \
      --exclude-dir='node_modules' \
      "$@" .
  fi

  # Handle convertable binary files
  find . -maxdepth 2 -type f \( \
    -name "*.epub" \
    -o -name "*.mobi" \
    -o -name "*.pdf" \) \
    -print0 2> /dev/null \
    | xargs -0 -I{} plaintext-detached.sh {} 2> /dev/null \
    | while IFS= read -r i; do
      if command -v rg > /dev/null 2>&1; then
        rg --smart-case \
          --follow \
          --max-columns 500 \
          --no-heading \
          --with-filename \
          --line-number \
          "$@" "$i"
      else
        grep -Hin \
          --extended-regexp \
          "$@" "$i"
      fi
    done
}

# `grep` with matches open in text editor.
ge() {
  entry=$(git-grep-detached.sh "$*")
  [ -z "$entry" ] && return
  filename=${entry//:*/}
  lineno=${entry#$filename:}
  gvim -v "$filename" +"$lineno"
}

gf() {
  git log \
    --color=always \
    --date=short \
    --format="%C(green)%C(bold)%cd %C(auto)%h%d %s" \
    --graph \
    | fzf \
      --ansi --multi --no-sort --reverse \
      --bind 'ctrl-s:toggle-sort' \
      --header 'ctrl-s:toggle-sort,ctrl-u:preview-page-down,ctrl-i:preview-page-up' \
      --preview-window 'right:65%' \
      --preview 'grep -o "[a-f0-9]\{7,\}" <<< {} | xargs git show --color=always | head -'$LINES \
    | grep -o "[a-f0-9]\{7,\}"
}

# Cross-platform open with default app
o() {
  local open_cmd
  case "$OSTYPE" in
  darwin*) open_cmd='open' ;;
  cygwin*) open_cmd='cygstart' ;;
  linux*) open_cmd='xdg-open' ;;
  msys*) open_cmd='start ""' ;;
  *)
    echo "Platform $OSTYPE not supported"
    return 1
    ;;
  esac
  while [ $# -gt 0 ]; do
    "$open_cmd" "$1"
    shift
  done
}

# `task` with output fitted to terminal height.
t() {
  if [ $# -gt 0 ]; then
    task "$@" || return
  fi
  clear
  script -qefc "task list; exit" /dev/null | head -n+$LINES
}

# `strings` with multiple encodings
x() {
  strings "$@"
  strings -eb "$@"
  strings -el "$@"
}

# colorize output
# Reference: `man terminfo`
c() {
  # foreground
  fn=$(tput sgr0) # turn off all attributes (i.e. normal text)
  fb=$(tput bold) # turn on bold (extra bright) mode
  
  # normal colours
  f0=$(tput setaf 0) # black
  f1=$(tput setaf 1) # red
  f2=$(tput setaf 2) # green
  f3=$(tput setaf 3) # yellow
  f4=$(tput setaf 4) # blue
  f5=$(tput setaf 5) # magenta
  f6=$(tput setaf 6) # cyan
  f7=$(tput setaf 7) # white

  sed '
    s/\b\(ERR\|ERROR\)\b\(.*\)/'"$fb$f1\1\2$fn"'/g;
    s/\b\(WARN\|WARNING\)\b\(.*\)/'"$fb$f5\1\2$fn"'/g;
    s/\b\(INFO\)\b\(.*\)/'"$fb$f2\1\2$fn"'/g;
  ' /dev/stdin
}
