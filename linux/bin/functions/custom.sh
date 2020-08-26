# Reference: https://akikoskinen.info/image-diffs-with-git/
diff-img() {
  compare "$2" "$1" png:- \
    | montage -geometry +4+4 "$2" - "$1" png:- \
    | display -title "$1" -
}

diff-dirs() {
  tree1=$(mktemp)
  tree2=$(mktemp)
  tree -d -L 3 "$1" > "$tree1"
  tree -d -L 3 "$2" > "$tree2"
  vim -d "$tree1" "$tree2"
  rm -f "$tree1" "$tree2"
}

dup-dirs() {
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
  ssh -R 12345:127.0.0.1:12345 -t "${*:1}" 'bash -c "bash --rcfile <(curl -s http://127.0.0.1:12345/sshrc)"'
}

verify-certificate() {
  curl --insecure -v "$1" 2>&1 | awk 'BEGIN { cert=0 } /^\* Server certificate:/ { cert=1 } /^\*/ { if (cert) print }'
}

man-cat() {
  #groff -te -mandoc -rHY=0 -Tascii <(zcat "$1") | sed -e "s/\x1b\[[^m]\{1,5\}m//g" | col -bx
  #find . -iname '*fc*' -print0 | xargs -0 -i sh -c 'zcat "$1" | grep -in charset && echo "$1"' _ {} | vim -
  find /usr/share/man -iname '*'"$1"'*gz' -print0 \
    | xargs -0 -i zcat {} \
    | groff -te -mandoc -rHY=0 -Tascii 2> /dev/null \
    | grep -i "$2"
}

jar-decompile() {
  while [ $# -gt 0 ]; do
    jar -xf "$1" && find . -iname "*.class" -print0 \
      | xargs -0 -i jad -r {}
    shift
  done
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

e() {
  entry=$(git-grep-detached.sh "$*")
  [ -z "$entry" ] && return
  filename=${entry//:*}
  lineno=${entry#$filename:}
  gvim -v "$filename" +"$lineno"
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

g() {
  # TODO: Manual recursion to handle specific file formats
  # e.g. pdftotext -enc UTF-8 "$target_file" -
  grep -Rin \
    --binary-files=without-match \
    --exclude-dir='.bzr' \
    --exclude-dir='.git' \
    --exclude-dir='.hg' \
    --exclude-dir='.svn' \
    --exclude-dir='__pycache__' \
    --exclude-dir='node_modules' \
    -- "$*" .
}

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
