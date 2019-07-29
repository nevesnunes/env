function cmpdirs() {
  tree -d -L 3 "$1" > tree1
  tree -d -L 3 "$2" > tree2
  vim -d tree1 tree2
  rm tree1 tree2
}

function dupdirs() {
  find "$1" -type f -exec basename {} \; | \
    sed 's/\(.*\)\..*/\1/' | sort | uniq -c | grep -v "^[ \t]*1 "
}

function ssh() {
    if [ "$(ps -p $(ps -p $$ -o ppid=) -o comm=)" = "tmux" ]; then
        tmux rename-window "$(echo $* | rev | cut -d ' ' -f1 | rev | cut -d . -f 1)"
        command ssh "$@"
        tmux set-window-option automatic-rename "on" 1>/dev/null
    else
        command ssh "$@"
    fi
}

function verify-certificate() {
    curl --insecure -v "$1" 2>&1 | awk 'BEGIN { cert=0 } /^\* Server certificate:/ { cert=1 } /^\*/ { if (cert) print }'
}
