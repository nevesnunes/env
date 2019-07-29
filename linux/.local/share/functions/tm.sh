function tm() {
  target_cd=$(tmux-wd.sh)
  if [ -d "$target_cd" ]; then
    "$@" "$target_cd/."
  else
    echo "Bad command directory."
    return 1
  fi
}

function tcp() {
  tm cp "$@"
}

function tmv() {
  tm mv "$@"
}
