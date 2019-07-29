diff-dirs() {
  tree1=$(mktemp)
  tree2=$(mktemp)
  tree -d -L 3 "$1" > "$tree1"
  tree -d -L 3 "$2" > "$tree2"
  vim -d "$tree1" "$tree2"
  rm -f "$tree1" "$tree2"
}

dup-dirs() {
  find "$1" -type f -exec basename {} \; | \
    sed 's/\(.*\)\..*/\1/' | \
    sort | \
    uniq -c | \
    grep -v "^[ \t]*1 "
}

ssh() {
    if [ "$(ps -p $(ps -p $$ -o ppid=) -o comm=)" = "tmux" ]; then
        tmux rename-window "$(echo $* | rev | cut -d ' ' -f1 | rev | cut -d . -f 1)"
        command ssh "$@"
        tmux set-window-option automatic-rename "on" 1>/dev/null
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
  for i in /usr/share/man/man*; do
    find "$i" -iname '*'"$1"'*gz' | \
      xargs -d'\n' -n1 -I{} zcat {} | \
      groff -te -mandoc -rHY=0 -Tascii | \
      grep -i "$2"
  done
}

jar-decompile() {
  jar -xf "$1" && find . -iname "*.class" | xargs jad -r
}

gf() {
    git log --date=short --format="%C(green)%C(bold)%cd %C(auto)%h%d %s" --graph --color=always | \
        fzf-down --ansi --no-sort --reverse --multi --bind 'ctrl-s:toggle-sort' \
        --header 'Press CTRL-S to toggle sort' \
        --preview 'grep -o "[a-f0-9]\{7,\}" <<< {} | xargs git show --color=always | head -'$LINES | \
        grep -o "[a-f0-9]\{7,\}"
}

f() {
  find . -iname '*'"$*"'*'
}

g() {
  grep -Rin -- "$*" .
}
