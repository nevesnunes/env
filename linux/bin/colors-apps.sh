# USAGE
# $1: Xresources filename

if [ -z "$1" ]; then
  echo "Bad filename."
  exit 1
fi

session=$(tmux display-message -p '#S')
function run_in_tmux() {
  tmux new-window
  tmux send-keys -t "$session:{end}" "$1 " "C-m"
}

run_in_tmux "colors.sh"
run_in_tmux "node ~/bin/wcag-check/index.js ~/.local/share/Xresources/$1"
run_in_tmux "htop"
  tmux send-keys -t "$session:{end}" "/asdf"
run_in_tmux "mc"
